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

//! VirusTotal relay.
//!
//! Why this exists: the VirusTotal API v3 does not emit CORS headers, so a
//! browser `fetch()` straight to `www.virustotal.com` is blocked by the
//! same-origin policy. This optional same-origin relay forwards the request for
//! the browser. It is *not* an open proxy — a valid IP-bound token is required —
//! and it never stores the API key: the key arrives per-request in the
//! `X-VT-Key` header and is handed to `curl` only through a stdin config file,
//! so it never appears in the process argument list (`ps`) or on disk.
//!
//! We shell out to the system `curl` (always present on Rocky/RHEL) rather than
//! linking a Rust TLS stack, which keeps the dependency tree MSRV-clean and the
//! binary tiny.

use crate::http_util::json_string;
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

/// Validate the request path the browser asked us to forward. We only ever talk
/// to the fixed VT host, and the path must address the v3 API.
fn valid_path(path: &str) -> bool {
    path.starts_with("/api/v3/")
        && path.len() <= 4096
        && !path.contains("://")
        && !path.chars().any(|c| c.is_whitespace() || (c as u32) < 0x20)
}

/// VirusTotal keys are hex; bound the length and charset so the value is safe to
/// drop into a curl config line.
fn valid_key(key: &str) -> bool {
    let len = key.len();
    (16..=128).contains(&len) && key.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Result of a relayed call: the upstream HTTP status and the parsed body.
pub struct RelayOut {
    pub status: u16,
    /// Raw JSON text of the VT response body (already valid JSON).
    pub body_json: String,
}

/// Forward one request to VirusTotal. `method` is GET or POST; `body` is the
/// optional JSON request body (only meaningful for POST).
pub fn relay(key: &str, path: &str, method: &str, body: Option<&Value>) -> Result<RelayOut, String> {
    if !valid_key(key) {
        return Err("malformed VirusTotal key".into());
    }
    if !valid_path(path) {
        return Err("path must address /api/v3/ on VirusTotal".into());
    }
    let method = method.to_ascii_uppercase();
    if method != "GET" && method != "POST" {
        return Err("only GET and POST are relayed".into());
    }

    let url = format!("https://www.virustotal.com{path}");

    let mut cmd = Command::new("curl");
    cmd.arg("-sS") // silent but show errors
        .arg("--fail-with-body") // still capture body on >=400
        .arg("--max-time")
        .arg("60")
        .arg("-A")
        .arg("IoCHub-relay/0.1")
        .arg("-X")
        .arg(&method)
        // Status code goes to stdout after the body, on its own line.
        .arg("-w")
        .arg("\n%{http_code}")
        // Read the x-apikey header from a config file on stdin (fd 0). Keeps the
        // secret out of argv.
        .arg("-K")
        .arg("-");

    // For POST with a JSON body, inline it as an argument; the body is not
    // secret (the key is). Content-Type set accordingly.
    if method == "POST" {
        if let Some(v) = body {
            cmd.arg("-H").arg("Content-Type: application/json");
            cmd.arg("--data-binary").arg(v.to_string());
        }
    }

    cmd.arg(&url);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("failed to launch curl: {e}"))?;

    // Write the curl config (the secret header) to stdin, then close it.
    {
        let stdin = child.stdin.as_mut().ok_or("no curl stdin")?;
        let cfg = format!("header = \"x-apikey: {key}\"\n");
        stdin.write_all(cfg.as_bytes()).map_err(|e| format!("curl stdin: {e}"))?;
    }

    let output = child.wait_with_output().map_err(|e| format!("curl wait: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Split trailing "\n<http_code>" off the end.
    let (body_part, code_part) = match stdout.rfind('\n') {
        Some(idx) => (&stdout[..idx], stdout[idx + 1..].trim()),
        None => (stdout.as_ref(), ""),
    };
    let status: u16 = code_part.parse().unwrap_or(0);

    if status == 0 {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("relay transport error: {}", err.trim()));
    }

    // Ensure the body we hand back is valid JSON. VT normally returns JSON; if
    // not, wrap the raw text so the browser still gets parseable output.
    let body_json = match serde_json::from_str::<Value>(body_part) {
        Ok(_) => body_part.to_string(),
        Err(_) => format!("{{\"raw\":{}}}", json_string(body_part)),
    };

    Ok(RelayOut { status, body_json })
}

/// Download a sample's raw bytes from VirusTotal (`/api/v3/files/{hash}/download`).
/// Returns the HTTP status and the raw bytes (caller base64-encodes for the
/// browser). VT answers with a 302 to a one-time download URL; `-L` follows it.
/// Requires a privileged key; non-privileged keys get 403 from VT.
pub fn download(key: &str, hash: &str) -> Result<(u16, Vec<u8>), String> {
    if !valid_key(key) {
        return Err("malformed VirusTotal key".into());
    }
    if hash.len() < 32 || hash.len() > 64 || !hash.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("malformed hash".into());
    }
    let url = format!("https://www.virustotal.com/api/v3/files/{hash}/download");

    let mut cmd = Command::new("curl");
    cmd.arg("-sS")
        .arg("-L") // follow VT's redirect to the actual bytes
        .arg("--max-time")
        .arg("300")
        .arg("-A")
        .arg("IoCHub-relay/0.1")
        // status code appended after the body on its own line is unsafe for
        // binary; instead write the code to stderr via -w and keep stdout pure.
        .arg("-w")
        .arg("%{http_code}")
        .arg("-o")
        .arg("-") // body to stdout
        .arg("-K")
        .arg("-");
    cmd.arg(&url);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("failed to launch curl: {e}"))?;
    {
        let stdin = child.stdin.as_mut().ok_or("no curl stdin")?;
        let cfg = format!("header = \"x-apikey: {key}\"\n");
        stdin.write_all(cfg.as_bytes()).map_err(|e| format!("curl stdin: {e}"))?;
    }
    let output = child.wait_with_output().map_err(|e| format!("curl wait: {e}"))?;
    // With -w "%{http_code}" and -o -, the body is on stdout and the 3-digit code
    // is appended to stdout at the very end. Split the trailing 3 bytes off.
    let mut bytes = output.stdout;
    if bytes.len() < 3 {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("relay transport error: {}", err.trim()));
    }
    let code_str = String::from_utf8_lossy(&bytes[bytes.len() - 3..]).to_string();
    let status: u16 = code_str.parse().unwrap_or(0);
    if status == 0 {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("relay transport error: {}", err.trim()));
    }
    bytes.truncate(bytes.len() - 3); // drop the appended status code
    Ok((status, bytes))
}
