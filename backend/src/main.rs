// IoCHub — Indicator-of-Compromise graph platform
// Copyright (C) 2026 vmarik
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. Distributed WITHOUT ANY WARRANTY. See the GNU General Public License
// for details; you should have received a copy with this program (LICENSE file),
// or see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! IoCHub backend entry point.
//!
//! A single statically-linkable ELF that:
//!   * serves the vendored frontend (static files) from `./public`,
//!   * provides IP-bound token auth (Argon2id passwords),
//!   * stores up to two graphs per user as JSON files,
//!   * relays VirusTotal API calls (the browser holds the key; see `vt.rs`),
//!   * drives an existing CAPEv2 instance over REST (see `cape.rs`).
//!
//! Designed for Rocky Linux / RHEL behind Apache (mod_proxy). Apache terminates
//! TLS and forwards `X-Forwarded-For`, which is how tokens learn the client IP.

mod auth;
mod cape;
mod host_analysis;
mod http_util;
mod static_engine;
mod store;
mod vt;

use http_util::{client_ip, client_ja3, header, json_string, read_body, send_json, Json};
use serde_json::Value;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::thread;
use store::{AppState, Store, QueryLogEntry, MAX_SLOTS};
use tiny_http::{Header, Method, Request, Response, Server};

const MAX_BODY: usize = 8 * 1024 * 1024; // 8 MiB cap on request bodies / graphs.
const MAX_CAPE_BODY: usize = 64 * 1024 * 1024; // legacy alias; small change-password payloads.
// Static analysis and CAPE submit can carry a base64-encoded sample. The
// frontend caps samples at 256 MB; base64 inflates that ~1.34x, so allow ~384
// MiB plus JSON overhead. Kept off MAX_BODY so ordinary endpoints stay tight.
// Static analysis / CAPE submit carry a base64-encoded sample. The browser now
// allows single-file analysis up to ~1 GB (the user owns their RAM); base64
// inflates that ~1.34x, so allow ~1.5 GiB plus JSON overhead.
const MAX_FILE_BODY: usize = 1536 * 1024 * 1024;
// Encrypted graph blobs (saved/autosaved) can get large on big investigations
// (hundreds of entities + sub-entities + attributes). Allow well above the
// generic 8 MiB so saves don't fail with "request body too large".
const MAX_GRAPH_BODY: usize = 96 * 1024 * 1024;

/// The seeded admin username (the only account permitted to create others).
const ADMIN_USER: &str = "vmarik";

/// The ONLY Entra ID tenant whose tokens are accepted for SSO. Logins whose
/// token tenant id (`tid`) differs are rejected. Overridable via env.
const ENTRA_TENANT_ID: &str = "00000000-0000-0000-0000-000000000000";
fn allowed_tenant() -> String {
    std::env::var("IOCHUB_ENTRA_TENANT").unwrap_or_else(|_| ENTRA_TENANT_ID.to_string())
}

/// Admin password used only to seed the admin's credential at first start.
/// Overridable via env so it need not live in the source for production.
fn admin_password() -> String {
    std::env::var("IOCHUB_ADMIN_PASSWORD")
        .unwrap_or_else(|_| "IoChUb".to_string())
}

fn main() {
    let addr = std::env::var("IOCHUB_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let data_dir = std::env::var("IOCHUB_DATA").unwrap_or_else(|_| "./data".to_string());
    let public_dir = std::env::var("IOCHUB_PUBLIC").unwrap_or_else(|_| "./public".to_string());
    let threads: usize =
        std::env::var("IOCHUB_THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(8);

    let store = Store::open(&data_dir).unwrap_or_else(|e| {
        eprintln!("fatal: cannot open data dir {data_dir}: {e}");
        std::process::exit(1);
    });

    let cape = cape::Manager::new(Path::new(&data_dir));

    let state = Arc::new(AppState {
        store: std::sync::Mutex::new(store),
        auth: std::sync::Mutex::new(auth::Auth::default()),
        public_dir: PathBuf::from(&public_dir),
        cape,
    });

    // Seed the admin account (the only account allowed to create others). Its
    // credential is derived exactly the way the browser will, so it can log in.
    {
        let mut store = state.store.lock().unwrap();
        if !store.user_exists(ADMIN_USER) {
            let secret = auth::derive_auth_secret(&admin_password(), ADMIN_USER);
            match auth::create_user(&mut store, ADMIN_USER, &secret, true) {
                Ok(()) => eprintln!("seeded admin user '{ADMIN_USER}'"),
                Err(e) => eprintln!("warning: could not seed admin '{ADMIN_USER}': {e}"),
            }
        }
    }

    let server = Arc::new(Server::http(&addr).unwrap_or_else(|e| {
        eprintln!("fatal: cannot bind {addr}: {e}");
        std::process::exit(1);
    }));

    eprintln!("iochub listening on http://{addr}  (data={data_dir} public={public_dir})");

    let mut handles = Vec::new();
    for _ in 0..threads.max(1) {
        let server = Arc::clone(&server);
        let state = Arc::clone(&state);
        handles.push(thread::spawn(move || loop {
            match server.recv() {
                Ok(req) => handle(req, &state),
                Err(e) => {
                    eprintln!("recv error: {e}");
                    break;
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

fn split_url(url: &str) -> (String, String) {
    match url.find('?') {
        Some(i) => (url[..i].to_string(), url[i + 1..].to_string()),
        None => (url.to_string(), String::new()),
    }
}

fn bearer(req: &Request) -> Option<String> {
    let h = header(req, "Authorization")?;
    let rest = h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer "))?;
    Some(rest.trim().to_string())
}

/// Authorize, returning the username or an error `Json` (401).
fn require_auth(req: &Request, state: &AppState) -> Result<String, Json> {
    let ip = client_ip(req);
    let ja3 = client_ja3(req);
    let token = bearer(req).ok_or_else(|| Json::err(401, "missing bearer token"))?;
    let mut a = state.auth.lock().unwrap();
    a.authorize(&token, &ip, ja3.as_deref()).ok_or_else(|| Json::err(401, "invalid token or source changed"))
}

fn handle(req: Request, state: &AppState) {
    let method = req.method().clone();
    let (path, query) = split_url(req.url());

    if path == "/healthz" {
        return send_json(req, Json::ok("{\"ok\":true,\"service\":\"iochub\"}".into()));
    }

    if let Some(rest) = path.strip_prefix("/api/") {
        return route_api(req, state, &method, &rest.to_string(), &query);
    }

    if method == Method::Get || method == Method::Head {
        return serve_static(req, state, &path);
    }

    send_json(req, Json::err(404, "not found"));
}

fn route_api(req: Request, state: &AppState, method: &Method, rest: &str, _query: &str) {
    match (method, rest) {
        (Method::Post, "auth/login") => h_login(req, state),
        (Method::Post, "auth/sso") => h_sso_login(req, state),
        (Method::Post, "auth/set_passphrase") => h_set_passphrase(req, state),
        (Method::Post, "auth/logout") => h_logout(req, state),
        (Method::Post, "auth/change_password") => h_change_password(req, state),
        (Method::Get, "me") => h_me(req, state),
        (Method::Post, "admin/create_user") => h_admin_create_user(req, state),
        (Method::Post, "query_log") => h_query_log_add(req, state),
        (Method::Get, "admin/query_log") => h_admin_query_log(req, state),
        (Method::Get, "vtkey") => h_vtkey_get(req, state),
        (Method::Put, "vtkey") => h_vtkey_put(req, state),
        (Method::Delete, "vtkey") => h_vtkey_delete(req, state),
        (Method::Get, "mispkey") => h_mispkey_get(req, state),
        (Method::Put, "mispkey") => h_mispkey_put(req, state),
        (Method::Delete, "mispkey") => h_mispkey_delete(req, state),
        (Method::Get, "graphs") => h_graphs_list(req, state),
        (Method::Post, "vt/relay") => h_vt_relay(req, state),
        (Method::Post, "vt/download") => h_vt_download(req, state),
        (Method::Post, "static/analyze") => h_static_analyze(req, state),
        (Method::Post, "host/domain") => h_host_domain(req, state),
        (Method::Post, "host/ip") => h_host_ip(req, state),
        (Method::Post, "cape/submit") => h_cape_submit(req, state),
        _ => {
            if let Some(slot_part) = rest.strip_prefix("graphs/") {
                return route_graph_slot(req, state, method, &slot_part.to_string());
            }
            if let Some(id) = rest.strip_prefix("cape/job/") {
                if *method == Method::Get {
                    if let Err(j) = require_auth(&req, state) {
                        return send_json(req, j);
                    }
                    return send_json(req, Json::ok(state.cape.job(id).to_string()));
                }
            }
            send_json(req, Json::err(404, "no such endpoint"));
        }
    }
}

/* ------------------------------- auth ---------------------------------- */

/// Parse `{username, secret}` where `secret` is the browser-derived auth value.
fn parse_login(body: &str) -> Result<(String, String), Json> {
    let v: Value = serde_json::from_str(body).map_err(|_| Json::err(400, "invalid JSON"))?;
    let u = v.get("username").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let s = v.get("secret").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if u.is_empty() || s.is_empty() {
        return Err(Json::err(400, "username and secret required"));
    }
    Ok((u, s))
}

/// Current Unix time in milliseconds (matches the frontend's Date.now()).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
fn is_admin(state: &AppState, user: &str) -> bool {
    state.store.lock().unwrap().get_user(user).map(|r| r.is_admin).unwrap_or(false)
}

fn h_login(mut req: Request, state: &AppState) {
    let ip = client_ip(&req);
    // Permissive fail2ban-style throttle: reject early if this IP is blocked.
    {
        let mut a = state.auth.lock().unwrap();
        if a.login_blocked(&ip) {
            let mins = a.login_block_remaining(&ip) / 60;
            return send_json(req, Json::err(429,
                &format!("too many failed logins from this IP — try again in ~{} min", mins.max(1))));
        }
    }
    let body = match read_body(&mut req, MAX_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    let (u, s) = match parse_login(&body) {
        Ok(c) => c,
        Err(j) => return send_json(req, j),
    };
    let admin = {
        let store = state.store.lock().unwrap();
        if let Err(e) = auth::check_login(&store, &u, &s) {
            // Record the failure against the source IP, then return.
            state.auth.lock().unwrap().record_login_failure(&ip);
            return send_json(req, Json::err(401, &e));
        }
        store.get_user(&u).map(|r| r.is_admin).unwrap_or(false)
    };
    let ja3 = client_ja3(&req);
    let token = {
        let mut a = state.auth.lock().unwrap();
        a.clear_login_failures(&ip);   // success wipes this IP's failure record
        a.issue(&u, &ip, ja3)
    };
    send_json(
        req,
        Json::ok(format!("{{\"token\":{},\"username\":{},\"is_admin\":{}}}", json_string(&token), json_string(&u), admin)),
    );
}

fn h_logout(req: Request, state: &AppState) {
    if let Some(tok) = bearer(&req) {
        state.auth.lock().unwrap().logout(&tok);
    }
    send_json(req, Json::ok("{\"ok\":true}".into()));
}

/// Decode the (base64url) payload of a JWT WITHOUT verifying its signature.
/// SKELETON ONLY: real Entra integration must verify the token signature
/// against the tenant's JWKS and validate aud/iss/exp. This is used to read the
/// claims so the rest of the SSO plumbing can be built and tested.
fn jwt_payload_unsafe(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    // base64url decode (no padding)
    let bytes = b64url_decode(payload_b64)?;
    serde_json::from_slice(&bytes).ok()
}
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    // convert base64url to standard base64 with padding, then decode
    let mut t = s.replace('-', "+").replace('_', "/");
    while t.len() % 4 != 0 { t.push('='); }
    <base64ct::Base64 as base64ct::Encoding>::decode_vec(&t).ok()
}

/// Entra ID SSO login (SKELETON). Accepts an Entra-issued ID token, checks the
/// tenant id (`tid`) matches the single allowed tenant, then upserts an SSO
/// account and issues an IoCHub session. SSO accounts start in server-side
/// encryption mode (the backend holds a per-user key) — see UserRecord docs.
///
/// NOTE: token SIGNATURE verification is NOT yet implemented (no live OAuth
/// flow). Until that's wired, this endpoint is gated off by default and must be
/// explicitly enabled with IOCHUB_ENABLE_SSO=1 so a half-verified path can't be
/// used in production by accident.
fn h_sso_login(mut req: Request, state: &AppState) {
    if std::env::var("IOCHUB_ENABLE_SSO").ok().as_deref() != Some("1") {
        return send_json(req, Json::err(503, "SSO is not enabled on this server yet (skeleton). Set IOCHUB_ENABLE_SSO=1 once the Entra OAuth flow is wired."));
    }
    let ip = client_ip(&req);
    let body = match read_body(&mut req, MAX_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let token = v.get("id_token").and_then(|x| x.as_str()).unwrap_or("");
    if token.is_empty() {
        return send_json(req, Json::err(400, "id_token required"));
    }
    let claims = match jwt_payload_unsafe(token) {
        Some(c) => c,
        None => return send_json(req, Json::err(400, "could not parse id_token")),
    };
    // Tenant restriction: only the configured tenant is accepted.
    let tid = claims.get("tid").and_then(|x| x.as_str()).unwrap_or("");
    if tid != allowed_tenant() {
        return send_json(req, Json::err(403, "this Entra tenant is not allowed to sign in"));
    }
    let oid = claims.get("oid").and_then(|x| x.as_str()).unwrap_or("");
    if oid.is_empty() {
        return send_json(req, Json::err(400, "token missing oid claim"));
    }
    // Username: prefer preferred_username/upn, sanitized.
    let raw_name = claims.get("preferred_username").and_then(|x| x.as_str())
        .or_else(|| claims.get("upn").and_then(|x| x.as_str()))
        .or_else(|| claims.get("email").and_then(|x| x.as_str()))
        .unwrap_or(oid);
    let username = sanitize_sso_username(raw_name);

    // Generate a per-user server-side key for option-A encryption.
    let key_b64 = {
        let mut buf = [0u8; 32];
        if getrandom::getrandom(&mut buf).is_err() {
            return send_json(req, Json::err(500, "rng failure"));
        }
        <base64ct::Base64 as base64ct::Encoding>::encode_string(&buf)
    };
    {
        let mut store = state.store.lock().unwrap();
        if let Err(e) = auth::upsert_sso_user(&mut store, &username, oid, &key_b64) {
            return send_json(req, Json::err(400, &e));
        }
    }
    let admin = is_admin(state, &username);
    let token = state.auth.lock().unwrap().issue(&username, &ip, client_ja3(&req));
    send_json(req, Json::ok(format!(
        "{{\"token\":{},\"username\":{},\"is_admin\":{},\"auth_source\":\"entra\"}}",
        json_string(&token), json_string(&username), admin
    )));
}
fn sanitize_sso_username(raw: &str) -> String {
    let s: String = raw.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@' { c } else { '_' })
        .collect();
    let s = s.trim_matches('_').to_string();
    if s.len() < 3 { format!("sso_{s}") } else if s.len() > 64 { s[..64].to_string() } else { s }
}

/// Set (or change) a graph passphrase for an SSO account — upgrades option A →
/// B (zero-knowledge). The browser sends the new auth secret (for login) plus
/// the content re-encrypted under its new browser key; we store the password
/// hash, clear the server-side key, and write the new graphs/VT blobs. After
/// this the server can no longer read the user's content.
fn h_set_passphrase(mut req: Request, state: &AppState) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    let body = match read_body(&mut req, MAX_CAPE_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let new_secret = v.get("new_secret").and_then(|x| x.as_str()).unwrap_or("");
    if new_secret.chars().count() < 16 {
        return send_json(req, Json::err(400, "new secret too short"));
    }
    let mut store = state.store.lock().unwrap();
    let mut rec = match store.get_user(&user) {
        Some(r) => r,
        None => return send_json(req, Json::err(404, "no such user")),
    };
    if rec.auth_source != "entra" {
        return send_json(req, Json::err(400, "passphrase upgrade is only for SSO accounts"));
    }
    let new_hash = match auth::hash_password(new_secret) {
        Ok(h) => h,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    // Re-write content (graphs + VT key) re-encrypted under the browser key.
    if let Some(graphs) = v.get("graphs").and_then(|g| g.as_object()) {
        for (slot, blob) in graphs {
            if let Ok(n) = slot.parse::<u8>() {
                if (1..=MAX_SLOTS).contains(&n) && !blob.is_null() {
                    let _ = store.write_graph(&user, n, &blob.to_string());
                }
            }
        }
    }
    if let Some(vt) = v.get("vt") {
        if !vt.is_null() { let _ = store.write_vt(&user, &vt.to_string()); }
    }
    rec.pw_hash = new_hash;
    rec.server_key_b64 = None;   // upgraded to zero-knowledge; server can no longer read
    match store.insert_user(rec) {
        Ok(()) => send_json(req, Json::ok("{\"ok\":true,\"mode\":\"zero-knowledge\"}".into())),
        Err(e) => send_json(req, Json::err(500, &format!("storage error: {e}"))),
    }
}

fn h_me(req: Request, state: &AppState) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    let rec = state.store.lock().unwrap().get_user(&user);
    let admin = rec.as_ref().map(|r| r.is_admin).unwrap_or(false);
    let auth_source = rec.as_ref().map(|r| r.auth_source.clone()).unwrap_or_else(|| "local".into());
    // server_key present => SSO account still in option-A (server can read);
    // can_set_passphrase tells the UI to offer the zero-knowledge upgrade.
    let server_side = rec.as_ref().map(|r| r.server_key_b64.is_some()).unwrap_or(false);
    send_json(req, Json::ok(format!(
        "{{\"username\":{},\"is_admin\":{},\"auth_source\":{},\"server_side_encryption\":{},\"can_set_passphrase\":{}}}",
        json_string(&user), admin, json_string(&auth_source), server_side, server_side
    )));
}

/// Admin-only: create a new (non-admin) account from a client-derived secret.
fn h_admin_create_user(mut req: Request, state: &AppState) {
    let actor = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    if !is_admin(state, &actor) {
        return send_json(req, Json::err(403, "only the admin can create accounts"));
    }
    let body = match read_body(&mut req, MAX_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    let (u, s) = match parse_login(&body) {
        Ok(c) => c,
        Err(j) => return send_json(req, j),
    };
    let mut store = state.store.lock().unwrap();
    match auth::create_user(&mut store, &u, &s, false) {
        Ok(()) => send_json(req, Json::ok(format!("{{\"ok\":true,\"username\":{}}}", json_string(&u)))),
        Err(e) => send_json(req, Json::err(400, &e)),
    }
}

/// Any authenticated user: record a VT query they hand-edited away from the
/// auto-built one. Persisted server-side (append-only) for admin review.
fn h_query_log_add(mut req: Request, state: &AppState) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    let body = match read_body(&mut req, MAX_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let final_query = v.get("final").or_else(|| v.get("final_query")).and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if final_query.is_empty() {
        return send_json(req, Json::err(400, "final query required"));
    }
    let auto_query = v.get("auto").or_else(|| v.get("auto_query")).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let attributes: Vec<String> = v.get("attributes").and_then(|a| a.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    // Cap field sizes so a client can't bloat the log.
    let clip = |s: String, n: usize| if s.len() > n { s[..n].to_string() } else { s };
    let entry = QueryLogEntry {
        ts: now_ms(),
        username: user,
        final_query: clip(final_query, 2000),
        auto_query: clip(auto_query, 2000),
        attributes: attributes.into_iter().take(50).map(|s| clip(s, 200)).collect(),
    };
    match state.store.lock().unwrap().append_query_log(entry) {
        Ok(()) => send_json(req, Json::ok("{\"ok\":true}".to_string())),
        Err(e) => send_json(req, Json::err(500, &format!("could not persist: {e}"))),
    }
}

/// Admin-only: list the persisted edited-query log (newest first).
fn h_admin_query_log(req: Request, state: &AppState) {
    let actor = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    if !is_admin(state, &actor) {
        return send_json(req, Json::err(403, "admin only"));
    }
    let mut entries = state.store.lock().unwrap().read_query_log();
    entries.reverse(); // newest first
    let items: Vec<String> = entries.iter().map(|e| {
        let attrs: Vec<String> = e.attributes.iter().map(|a| json_string(a)).collect();
        format!(
            "{{\"ts\":{},\"username\":{},\"final\":{},\"auto\":{},\"attributes\":[{}]}}",
            e.ts, json_string(&e.username), json_string(&e.final_query), json_string(&e.auto_query), attrs.join(",")
        )
    }).collect();
    send_json(req, Json::ok(format!("{{\"entries\":[{}]}}", items.join(","))));
}

/// Change the caller's password. The browser sends the old + new auth secrets
/// and the content (graphs + VT key) re-encrypted under the new key, so the
/// swap is atomic: nothing is ever left encrypted under a key the server no
/// longer expects.
fn h_change_password(mut req: Request, state: &AppState) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    let body = match read_body(&mut req, MAX_CAPE_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    let v: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return send_json(req, Json::err(400, "invalid JSON")),
    };
    let old = v.get("old_secret").and_then(|x| x.as_str()).unwrap_or("");
    let new = v.get("new_secret").and_then(|x| x.as_str()).unwrap_or("");
    if old.is_empty() || new.chars().count() < 16 {
        return send_json(req, Json::err(400, "old_secret and a valid new_secret are required"));
    }

    let mut store = state.store.lock().unwrap();
    let rec = match store.get_user(&user) {
        Some(r) => r,
        None => return send_json(req, Json::err(404, "no such user")),
    };
    if !auth::verify_password(old, &rec.pw_hash) {
        return send_json(req, Json::err(401, "current password is incorrect"));
    }
    let new_hash = match auth::hash_password(new) {
        Ok(h) => h,
        Err(e) => return send_json(req, Json::err(500, &e)),
    };
    if let Err(e) = store.update_password(&user, &new_hash) {
        return send_json(req, Json::err(500, &format!("storage error: {e}")));
    }
    // Re-write content re-encrypted under the new key (slots not sent are left
    // as-is on the assumption they were empty).
    if let Some(graphs) = v.get("graphs").and_then(|g| g.as_object()) {
        for (slot, blob) in graphs {
            if let Ok(n) = slot.parse::<u8>() {
                if (1..=MAX_SLOTS).contains(&n) && !blob.is_null() {
                    let _ = store.write_graph(&user, n, &blob.to_string());
                }
            }
        }
    }
    match v.get("vt") {
        Some(b) if !b.is_null() => { let _ = store.write_vt(&user, &b.to_string()); }
        _ => {}
    }
    send_json(req, Json::ok("{\"ok\":true}".into()));
}

/* ------------------------------ VT key --------------------------------- */

fn h_vtkey_get(req: Request, state: &AppState) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    match state.store.lock().unwrap().read_vt(&user) {
        Some(blob) => send_json(req, Json::ok(blob)),
        None => send_json(req, Json::ok("{\"empty\":true}".into())),
    }
}

fn h_vtkey_put(mut req: Request, state: &AppState) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    let body = match read_body(&mut req, MAX_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    if serde_json::from_str::<Value>(&body).is_err() {
        return send_json(req, Json::err(400, "vt blob must be JSON"));
    }
    match state.store.lock().unwrap().write_vt(&user, &body) {
        Ok(()) => send_json(req, Json::ok("{\"ok\":true}".into())),
        Err(e) => send_json(req, Json::err(500, &format!("storage error: {e}"))),
    }
}

fn h_vtkey_delete(req: Request, state: &AppState) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    state.store.lock().unwrap().delete_vt(&user);
    send_json(req, Json::ok("{\"ok\":true}".into()));
}

fn h_mispkey_get(req: Request, state: &AppState) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    match state.store.lock().unwrap().read_misp(&user) {
        Some(blob) => send_json(req, Json::ok(blob)),
        None => send_json(req, Json::ok("{\"empty\":true}".into())),
    }
}

fn h_mispkey_put(mut req: Request, state: &AppState) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    let body = match read_body(&mut req, MAX_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    if serde_json::from_str::<Value>(&body).is_err() {
        return send_json(req, Json::err(400, "misp blob must be JSON"));
    }
    match state.store.lock().unwrap().write_misp(&user, &body) {
        Ok(()) => send_json(req, Json::ok("{\"ok\":true}".into())),
        Err(e) => send_json(req, Json::err(500, &format!("storage error: {e}"))),
    }
}

fn h_mispkey_delete(req: Request, state: &AppState) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    state.store.lock().unwrap().delete_misp(&user);
    send_json(req, Json::ok("{\"ok\":true}".into()));
}

/* ------------------------------ graphs --------------------------------- */

fn h_graphs_list(req: Request, state: &AppState) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    let slots = state.store.lock().unwrap().list_slots(&user);
    let arr: Vec<String> = slots.iter().map(|s| s.to_string()).collect();
    send_json(
        req,
        Json::ok(format!("{{\"slots\":[{}],\"max\":{}}}", arr.join(","), MAX_SLOTS)),
    );
}

fn parse_slot(s: &str) -> Option<u8> {
    let head = s.split('/').next().unwrap_or("");
    match head.parse::<u8>() {
        Ok(n) if (1..=MAX_SLOTS).contains(&n) => Some(n),
        _ => None,
    }
}

fn route_graph_slot(req: Request, state: &AppState, method: &Method, slot_part: &str) {
    let slot = match parse_slot(slot_part) {
        Some(n) => n,
        None => return send_json(req, Json::err(400, "slot must be 1, 2, or 3")),
    };
    let is_download = slot_part.split('/').nth(1) == Some("download");

    match method {
        Method::Get => h_graph_get(req, state, slot, is_download),
        Method::Put => h_graph_put(req, state, slot),
        _ => send_json(req, Json::err(405, "method not allowed")),
    }
}

fn h_graph_get(req: Request, state: &AppState, slot: u8, is_download: bool) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    let graph = state.store.lock().unwrap().read_graph(&user, slot);
    match graph {
        Some(json) => {
            if is_download {
                let data = json.into_bytes();
                let ct = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
                let cd = Header::from_bytes(
                    &b"Content-Disposition"[..],
                    format!("attachment; filename=\"iochub-slot{slot}.json\"").as_bytes(),
                )
                .unwrap();
                let resp = Response::from_data(data).with_header(ct).with_header(cd);
                let _ = req.respond(resp);
            } else {
                send_json(req, Json::ok(json));
            }
        }
        None => send_json(req, Json::ok("{\"empty\":true}".into())),
    }
}

fn h_graph_put(mut req: Request, state: &AppState, slot: u8) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    let body = match read_body(&mut req, MAX_GRAPH_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    // Validate it parses as JSON before persisting.
    if serde_json::from_str::<Value>(&body).is_err() {
        return send_json(req, Json::err(400, "graph body must be JSON"));
    }
    match state.store.lock().unwrap().write_graph(&user, slot, &body) {
        Ok(()) => send_json(req, Json::ok(format!("{{\"ok\":true,\"slot\":{slot}}}"))),
        Err(e) => send_json(req, Json::err(500, &format!("storage error: {e}"))),
    }
}

/* -------------------------------- VT ----------------------------------- */

fn h_vt_relay(mut req: Request, state: &AppState) {
    if let Err(j) = require_auth(&req, state) {
        return send_json(req, j);
    }
    let key = match header(&req, "X-VT-Key") {
        Some(k) => k,
        None => return send_json(req, Json::err(400, "missing X-VT-Key header")),
    };
    let body = match read_body(&mut req, MAX_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    let v: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return send_json(req, Json::err(400, "invalid JSON")),
    };
    let path = v.get("path").and_then(|x| x.as_str()).unwrap_or("");
    let method = v.get("method").and_then(|x| x.as_str()).unwrap_or("GET");
    let vt_body = v.get("body").filter(|b| !b.is_null());

    match vt::relay(&key, path, method, vt_body) {
        Ok(out) => {
            // Shape: {"status":<code>,"body":<vt json>} — matches the frontend.
            let payload = format!("{{\"status\":{},\"body\":{}}}", out.status, out.body_json);
            send_json(req, Json::ok(payload))
        }
        Err(e) => send_json(req, Json::err(502, &e)),
    }
}

/// Download a sample's bytes from VirusTotal and hand them to the browser as
/// base64. Used when a hash-only entity needs bytes (static analysis / CAPE).
fn h_vt_download(mut req: Request, state: &AppState) {
    if let Err(j) = require_auth(&req, state) {
        return send_json(req, j);
    }
    let key = match header(&req, "X-VT-Key") {
        Some(k) => k,
        None => return send_json(req, Json::err(400, "missing X-VT-Key header")),
    };
    let body = match read_body(&mut req, MAX_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    let v: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return send_json(req, Json::err(400, "invalid JSON")),
    };
    let hash = v.get("sha256").or_else(|| v.get("hash")).and_then(|x| x.as_str()).unwrap_or("");
    match vt::download(&key, hash) {
        Ok((status, bytes)) => {
            if status >= 400 {
                let detail = if status == 403 {
                    "VirusTotal returned 403 — downloading samples requires a privileged (premium) API key."
                } else if status == 404 {
                    "VirusTotal has no downloadable sample for this hash (404)."
                } else {
                    "VirusTotal download failed."
                };
                return send_json(req, Json::ok(format!("{{\"status\":{status},\"detail\":{}}}", json_string(detail))));
            }
            let b64 = <base64ct::Base64 as base64ct::Encoding>::encode_string(&bytes);
            send_json(req, Json::ok(format!("{{\"status\":{status},\"size\":{},\"content_b64\":{}}}", bytes.len(), json_string(&b64))))
        }
        Err(e) => send_json(req, Json::err(502, &e)),
    }
}

/* ------------------------------- CAPE ---------------------------------- */

fn h_cape_submit(mut req: Request, state: &AppState) {
    let user = match require_auth(&req, state) {
        Ok(u) => u,
        Err(j) => return send_json(req, j),
    };
    let cfg = state.cape.config();
    if !state.cape.user_allowed(&cfg, &user) {
        return send_json(req, Json::err(403, "your account is not permitted to use CAPE"));
    }
    let body = read_body(&mut req, MAX_FILE_BODY).unwrap_or_default();
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let result = state.cape.submit(&cfg, &v);
    send_json(req, Json::ok(result.to_string()));
}

/* -------------------------- static analysis ---------------------------- */

fn h_static_analyze(mut req: Request, state: &AppState) {
    if let Err(j) = require_auth(&req, state) {
        return send_json(req, j);
    }
    let body = match read_body(&mut req, MAX_FILE_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    let v: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return send_json(req, Json::err(400, "invalid JSON")),
    };
    let b64 = match v.get("content_b64").and_then(|x| x.as_str()) {
        Some(s) => s,
        None => return send_json(req, Json::err(400, "content_b64 required")),
    };
    let bytes = match <base64ct::Base64 as base64ct::Encoding>::decode_vec(b64) {
        Ok(b) => b,
        Err(_) => return send_json(req, Json::err(400, "content_b64 is not valid base64")),
    };
    if bytes.is_empty() {
        return send_json(req, Json::err(400, "empty file"));
    }
    let filename = v.get("filename").and_then(|x| x.as_str());
    let result = static_engine::analyze(&bytes, filename);
    send_json(req, Json::ok(format!("{{\"attributes\":{}}}", result)));
}

/* -------------------------- host analysis ------------------------------ */

fn h_host_domain(mut req: Request, state: &AppState) {
    if let Err(j) = require_auth(&req, state) {
        return send_json(req, j);
    }
    let body = match read_body(&mut req, MAX_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let domain = v.get("domain").and_then(|x| x.as_str()).unwrap_or("").trim().to_lowercase();
    if domain.is_empty() {
        return send_json(req, Json::err(400, "domain required"));
    }
    // dig/whois/openssl can each take a little while; run synchronously.
    let result = host_analysis::analyze_domain(&domain);
    if result.get("error").is_some() {
        return send_json(req, Json::err(400, result.get("error").and_then(|e| e.as_str()).unwrap_or("error")));
    }
    send_json(req, Json::ok(result.to_string()));
}

fn h_host_ip(mut req: Request, state: &AppState) {
    if let Err(j) = require_auth(&req, state) {
        return send_json(req, j);
    }
    let body = match read_body(&mut req, MAX_BODY) {
        Ok(b) => b,
        Err(e) => return send_json(req, Json::err(400, &e)),
    };
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let ip = v.get("ip").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if ip.is_empty() {
        return send_json(req, Json::err(400, "ip required"));
    }
    let result = host_analysis::analyze_ip(&ip);
    if result.get("error").is_some() {
        return send_json(req, Json::err(400, result.get("error").and_then(|e| e.as_str()).unwrap_or("error")));
    }
    send_json(req, Json::ok(result.to_string()));
}

/* ----------------------------- static ---------------------------------- */

fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// Resolve a URL path to a file inside `public_dir`, rejecting traversal.
fn safe_path(public_dir: &Path, url_path: &str) -> Option<PathBuf> {
    let rel = url_path.trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    let candidate = Path::new(rel);
    // Reject any non-normal component (.., absolute, prefix, root).
    for c in candidate.components() {
        match c {
            Component::Normal(_) => {}
            _ => return None,
        }
    }
    Some(public_dir.join(candidate))
}

fn serve_static(req: Request, state: &AppState, url_path: &str) {
    let path = match safe_path(&state.public_dir, url_path) {
        Some(p) => p,
        None => return send_json(req, Json::err(403, "forbidden")),
    };
    match std::fs::read(&path) {
        Ok(bytes) => {
            let ct = content_type(path.to_str().unwrap_or(""));
            let header = Header::from_bytes(&b"Content-Type"[..], ct.as_bytes()).unwrap();
            let resp = Response::from_data(bytes).with_header(header);
            let _ = req.respond(resp);
        }
        Err(_) => {
            // SPA fallback: unknown non-asset path returns index.html so the app
            // can boot, but only for paths without a file extension.
            if !url_path.contains('.') {
                if let Some(idx) = safe_path(&state.public_dir, "index.html") {
                    if let Ok(bytes) = std::fs::read(idx) {
                        let header = Header::from_bytes(
                            &b"Content-Type"[..],
                            &b"text/html; charset=utf-8"[..],
                        )
                        .unwrap();
                        let resp = Response::from_data(bytes).with_header(header);
                        let _ = req.respond(resp);
                        return;
                    }
                }
            }
            send_json(req, Json::err(404, "not found"));
        }
    }
}
