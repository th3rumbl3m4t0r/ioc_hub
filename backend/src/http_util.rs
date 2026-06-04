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

//! Small HTTP helpers built on top of `tiny_http`: JSON responses, body
//! reading, header lookup, and client-IP extraction.

use std::io::Read;
use tiny_http::{Header, Request, Response};

/// A JSON response body paired with an HTTP status code.
pub struct Json {
    pub status: u16,
    pub body: String,
}

impl Json {
    pub fn new(status: u16, body: String) -> Self {
        Json { status, body }
    }

    /// `{"ok":true,...}` style payload from a raw JSON value string.
    pub fn ok(value: String) -> Self {
        Json::new(200, value)
    }

    /// `{"error":"..."}` payload with the given status.
    pub fn err(status: u16, msg: &str) -> Self {
        Json::new(status, format!("{{\"error\":{}}}", json_string(msg)))
    }
}

/// Send a `Json` value as an `application/json` response.
pub fn send_json(req: Request, j: Json) {
    let data = j.body.into_bytes();
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json; charset=utf-8"[..])
        .expect("static header");
    let resp = Response::from_data(data).with_status_code(j.status).with_header(header);
    let _ = req.respond(resp);
}

/// Read the full request body into a `String` (UTF-8 lossy), capped at `max` bytes.
pub fn read_body(req: &mut Request, max: usize) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut handle = req.as_reader().take((max as u64) + 1);
    handle.read_to_end(&mut buf).map_err(|e| format!("read error: {e}"))?;
    if buf.len() > max {
        return Err("request body too large".into());
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Case-insensitive header lookup, returning the header value as a `String`.
pub fn header(req: &Request, name: &str) -> Option<String> {
    for h in req.headers() {
        if h.field.as_str().as_str().eq_ignore_ascii_case(name) {
            return Some(h.value.as_str().to_owned());
        }
    }
    None
}

/// Determine the client IP used to bind a token.
///
/// When Apache reverse-proxies the backend it sets `X-Forwarded-For`; we take
/// the first hop (the original client). If absent we fall back to the socket
/// peer address. Only the IP portion is kept (port stripped).
pub fn client_ip(req: &Request) -> String {
    if let Some(xff) = header(req, "X-Forwarded-For") {
        if let Some(first) = xff.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    match req.remote_addr() {
        Some(addr) => addr.ip().to_string(),
        None => "0.0.0.0".to_string(),
    }
}

/// The request header carrying a TLS JA3 fingerprint, if JA3 fallback is
/// enabled. Set `IOCHUB_JA3_HEADER` (e.g. `X-JA3-Hash`) to the header your
/// TLS-terminating edge populates. When unset/empty, JA3 fallback is OFF and
/// token binding is pure source-IP (unchanged behaviour).
///
/// SECURITY: the backend trusts this header. It is only safe because (a) the
/// backend listens on 127.0.0.1 so only the local reverse proxy reaches it, and
/// (b) the edge that sets it MUST strip/overwrite any client-supplied copy of
/// the same header (a client must never be able to choose its own JA3).
pub fn ja3_header_name() -> Option<String> {
    match std::env::var("IOCHUB_JA3_HEADER") {
        Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        _ => None,
    }
}

/// Read the client's JA3 fingerprint from the configured trusted header, if
/// JA3 fallback is enabled and the header is present. Returns None when JA3 is
/// disabled or the edge did not supply a fingerprint for this request.
pub fn client_ja3(req: &Request) -> Option<String> {
    let name = ja3_header_name()?;
    let v = header(req, &name)?;
    let v = v.trim();
    // JA3 is an md5 hex digest (32 hex chars); accept that or a raw JA3 string,
    // but bound the length and reject anything with control/whitespace so a
    // malformed header can't poison the session map.
    if v.is_empty() || v.len() > 128 || v.chars().any(|c| c.is_whitespace() || (c as u32) < 0x20) {
        return None;
    }
    Some(v.to_string())
}

/// Escape a string as a JSON string literal (including the surrounding quotes).
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
