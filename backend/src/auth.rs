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

//! Authentication: Argon2id password hashing plus in-memory, IP-bound bearer
//! tokens.
//!
//! Tokens are kept only in memory (a `HashMap`), so a backend restart logs
//! everyone out. Per spec, permanence is deliberately traded away for
//! simplicity and security. Each token records the source IP it was issued to;
//! if a later request presents the token from a different IP it is rejected.

use crate::store::{Store, UserRecord};
use argon2::Argon2;
use base64ct::{Base64, Encoding};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Token lifetime in seconds (8 hours). A SOC shift, roughly.
const TOKEN_TTL_SECS: u64 = 8 * 60 * 60;

/// PBKDF2 work factor. MUST match the browser (app.js KDF_ITERS).
pub const KDF_ITERS: u32 = 210_000;

/// Deterministic per-user salt label for the *auth* secret. MUST match app.js.
fn auth_salt(username: &str) -> String {
    format!("iochub-auth-v1:{username}")
}

/// Reproduce the browser's auth-secret derivation: PBKDF2-HMAC-SHA256 over the
/// password with a per-user salt, base64 (standard, padded). The browser sends
/// exactly this value as the login credential; the raw password never leaves
/// the client. Used to seed the admin account server-side.
pub fn derive_auth_secret(password: &str, username: &str) -> String {
    let salt = auth_salt(username);
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), KDF_ITERS, &mut out);
    Base64::encode_string(&out)
}

pub struct Session {
    pub username: String,
    pub ip: String,
    pub created: u64,
}

/// Per-IP failed-login tracking for a permissive fail2ban-style throttle.
/// `fails` holds the unix-second timestamps of recent failed attempts (pruned
/// to the rolling window); `blocked_until` is set once the threshold trips.
#[derive(Default)]
struct LoginFails {
    fails: Vec<u64>,
    blocked_until: u64,
}

// Permissive thresholds (deliberately lax — this is a backstop against runaway
// brute force, not a tight lockout). 150 failures within an hour blocks the IP
// for 24h. Argon2id already makes online guessing slow; this just caps abuse.
const LOGIN_FAIL_WINDOW_SECS: u64 = 3600;       // 1 hour rolling window
const LOGIN_FAIL_THRESHOLD: usize = 150;        // failures in the window to trip
const LOGIN_BLOCK_SECS: u64 = 24 * 3600;        // 24 hour block

#[derive(Default)]
pub struct Auth {
    tokens: HashMap<String, Session>,
    login_fails: HashMap<String, LoginFails>,
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// 256 bits of CSPRNG output, hex-encoded, used as an opaque bearer token.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Hash a password with Argon2id using a fresh random salt. Returns a
/// PHC-format string safe to store at rest.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut password_hash::rand_core::OsRng);
    let argon = Argon2::default(); // Argon2id, sensible default params.
    argon
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("hash error: {e}"))
}

/// Verify a candidate password against a stored PHC hash string.
pub fn verify_password(password: &str, stored: &str) -> bool {
    let parsed = match PasswordHash::new(stored) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

impl Auth {
    /// Issue a token bound to `username` + `ip`.
    pub fn issue(&mut self, username: &str, ip: &str) -> String {
        let token = random_token();
        self.tokens.insert(
            token.clone(),
            Session { username: username.to_string(), ip: ip.to_string(), created: now() },
        );
        token
    }

    pub fn logout(&mut self, token: &str) {
        self.tokens.remove(token);
    }

    /// Resolve a token to a username, enforcing IP binding and TTL.
    ///
    /// A request from a different source IP is rejected but the session is
    /// preserved, so the legitimate IP keeps working (the token is *tied* to its
    /// origin IP, not destroyed by anyone who replays it elsewhere). Only true
    /// expiry purges the entry.
    pub fn authorize(&mut self, token: &str, ip: &str) -> Option<String> {
        match self.tokens.get(token) {
            Some(s) => {
                if now().saturating_sub(s.created) > TOKEN_TTL_SECS {
                    self.tokens.remove(token);
                    return None;
                }
                if s.ip != ip {
                    return None;
                }
                Some(s.username.clone())
            }
            None => None,
        }
    }

    /// Is this IP currently blocked from logging in (too many recent failures)?
    /// If the block has expired, it is cleared as a side effect.
    pub fn login_blocked(&mut self, ip: &str) -> bool {
        if let Some(rec) = self.login_fails.get_mut(ip) {
            if rec.blocked_until > now() {
                return true;
            }
            if rec.blocked_until != 0 {
                // block expired — reset this IP's record
                rec.blocked_until = 0;
                rec.fails.clear();
            }
        }
        false
    }

    /// Seconds remaining on an IP's block (0 if not blocked).
    pub fn login_block_remaining(&self, ip: &str) -> u64 {
        self.login_fails.get(ip)
            .map(|r| r.blocked_until.saturating_sub(now()))
            .unwrap_or(0)
    }

    /// Record a failed login from `ip`. Prunes attempts outside the rolling
    /// window, then trips a block if the threshold is reached.
    pub fn record_login_failure(&mut self, ip: &str) {
        let t = now();
        let rec = self.login_fails.entry(ip.to_string()).or_default();
        rec.fails.retain(|&ts| t.saturating_sub(ts) < LOGIN_FAIL_WINDOW_SECS);
        rec.fails.push(t);
        if rec.fails.len() >= LOGIN_FAIL_THRESHOLD {
            rec.blocked_until = t + LOGIN_BLOCK_SECS;
        }
        // Opportunistic cleanup so the map can't grow without bound from IPs
        // that hit a single failure long ago and never came back.
        if self.login_fails.len() > 10_000 {
            self.login_fails.retain(|_, r| r.blocked_until > t
                || r.fails.iter().any(|&ts| t.saturating_sub(ts) < LOGIN_FAIL_WINDOW_SECS));
        }
    }

    /// Clear an IP's failure record on a successful login.
    pub fn clear_login_failures(&mut self, ip: &str) {
        self.login_fails.remove(ip);
    }
}

/// Basic username policy: 3..=64 chars, alnum plus `-` `_` `.`.
pub fn valid_username(u: &str) -> bool {
    let len = u.chars().count();
    (3..=64).contains(&len)
        && u.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Create a new user from a client-derived auth secret. `secret` is the value
/// the browser derived from the password (never the raw password). Fails if the
/// username exists or is invalid.
pub fn create_user(store: &mut Store, username: &str, secret: &str, is_admin: bool) -> Result<(), String> {
    if !valid_username(username) {
        return Err("invalid username (3-64 chars: letters, digits, - _ .)".into());
    }
    if secret.chars().count() < 16 {
        return Err("auth secret too short (client derivation failed?)".into());
    }
    if store.user_exists(username) {
        return Err("username already taken".into());
    }
    let pw_hash = hash_password(secret)?;
    store
        .insert_user(UserRecord {
            username: username.to_string(),
            pw_hash,
            created: now(),
            is_admin,
            auth_source: "local".to_string(),
            server_key_b64: None,
            entra_oid: None,
        })
        .map_err(|e| format!("storage error: {e}"))
}

/// Create (or fetch) an Entra/SSO-backed account. SSO users start in option-A
/// mode: the backend holds a per-user `server_key_b64` so their graphs are
/// always encrypted at rest (no browser-side key needed). They can later set a
/// passphrase to upgrade to zero-knowledge. `server_key_b64` is a freshly
/// generated random key supplied by the caller.
pub fn upsert_sso_user(
    store: &mut Store,
    username: &str,
    entra_oid: &str,
    server_key_b64: &str,
) -> Result<(), String> {
    // SSO usernames come from UPN/email, so allow '@' (the strict local
    // validator does not). Still bound length and reject path/control chars.
    let valid_sso = {
        let len = username.chars().count();
        (3..=64).contains(&len)
            && username.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
    };
    if !valid_sso {
        return Err("invalid SSO username".into());
    }
    if let Some(mut rec) = store.get_user(username) {
        // Existing account — only allow SSO login if it's an SSO account bound
        // to the same Entra object id (don't let SSO hijack a local account).
        if rec.auth_source != "entra" {
            return Err("an account with this name already exists (local)".into());
        }
        if rec.entra_oid.as_deref().unwrap_or("") != entra_oid {
            return Err("SSO identity mismatch for this account".into());
        }
        // keep existing key (and any passphrase upgrade) intact
        if rec.server_key_b64.is_none() && rec.pw_hash.is_empty() {
            rec.server_key_b64 = Some(server_key_b64.to_string());
            return store.insert_user(rec).map_err(|e| format!("storage error: {e}"));
        }
        return Ok(());
    }
    store
        .insert_user(UserRecord {
            username: username.to_string(),
            pw_hash: String::new(),
            created: now(),
            is_admin: false,
            auth_source: "entra".to_string(),
            server_key_b64: Some(server_key_b64.to_string()),
            entra_oid: Some(entra_oid.to_string()),
        })
        .map_err(|e| format!("storage error: {e}"))
}

/// Check a login: the browser sends the derived auth secret, we verify it
/// against the stored Argon2id hash.
pub fn check_login(store: &Store, username: &str, secret: &str) -> Result<(), String> {
    let rec = store.get_user(username).ok_or_else(|| "invalid credentials".to_string())?;
    if verify_password(secret, &rec.pw_hash) {
        Ok(())
    } else {
        Err("invalid credentials".into())
    }
}
