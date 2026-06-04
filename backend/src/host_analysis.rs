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

//! Active host analysis (ad-hoc, operator-initiated).
//!
//! Unlike the static engine (which only inspects bytes) this module performs
//! *live* lookups against the target, by shelling out to standard system tools:
//!
//!   * domains: `dig` (A/AAAA resolutions), `whois` (registration record), and
//!     `openssl s_client` (TLS certificate over :443),
//!   * IPs: `nmap` (open ports + service/version detection).
//!
//! Output is shaped to VirusTotal's file/domain/ip nomenclature so the same
//! attribute table, sub-entity rendering, and pivot facets apply regardless of
//! whether a value came from VT or from here. Resolutions are returned
//! separately so the caller can add only the non-overlapping ones to the graph.
//!
//! Everything is best-effort and bounded by timeouts; a tool that is missing or
//! errors simply yields no fields for its part (the analysis never hard-fails).

use serde_json::{json, Map, Value};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Cap on how long any single external command may run.
const CMD_TIMEOUT_SECS: u64 = 120;

/// Run a command with a timeout, returning stdout as a String (empty on any
/// failure). We implement the timeout by spawning and polling, then killing.
fn run(cmd: &str, args: &[&str], timeout: Duration) -> String {
    let child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }
    match child.wait_with_output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => String::new(),
    }
}

/// Run two commands connected by a pipe (cmd1 stdout -> cmd2 stdin), with a
/// timeout on the downstream process. Pure argv, NO shell — so neither command
/// is subject to shell metacharacter injection. Returns cmd2's stdout (empty on
/// any failure). cmd1's stdin is closed (replaces a leading `echo |`).
fn run_piped(c1: (&str, &[&str]), c2: (&str, &[&str]), timeout: Duration) -> String {
    let mut p1 = match Command::new(c1.0).args(c1.1)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    let p1_out = match p1.stdout.take() {
        Some(o) => o,
        None => { let _ = p1.kill(); let _ = p1.wait(); return String::new(); }
    };
    // Feed cmd1's stdout directly into cmd2's stdin via the OS pipe fd.
    let mut p2 = match Command::new(c2.0).args(c2.1)
        .stdin(Stdio::from(p1_out)).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
        Ok(c) => c,
        Err(_) => { let _ = p1.kill(); let _ = p1.wait(); return String::new(); }
    };
    // Timeout: poll the downstream process, then kill both if it overruns.
    let start = std::time::Instant::now();
    loop {
        match p2.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = p2.kill(); let _ = p2.wait();
                    let _ = p1.kill(); let _ = p1.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }
    let out = p2.wait_with_output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    // Reap cmd1 so it doesn't linger as a zombie (it exits once its pipe closes).
    let _ = p1.kill();
    let _ = p1.wait();
    out
}

fn tool_exists(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/* ============================== domains ================================= */

/// Validate a domain so it can't be turned into shell/argument injection.
fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && !d.starts_with('-')
}

fn valid_ip(s: &str) -> bool {
    // IPv4 or IPv6 literal characters only.
    !s.is_empty()
        && s.len() <= 45
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
}

/// Analyze a domain: resolutions (dig), whois, and the TLS certificate.
/// Returns `{ attributes: {...VT-shaped...}, resolutions: ["ip", ...] }`.
pub fn analyze_domain(domain: &str) -> Value {
    if !valid_domain(domain) {
        return json!({"error": "invalid domain"});
    }
    let to = Duration::from_secs(CMD_TIMEOUT_SECS);
    let mut out = Map::new();
    let mut resolutions: Vec<String> = Vec::new();

    // ---- resolutions via dig (A + AAAA) ----
    if tool_exists("dig") {
        for rrtype in ["A", "AAAA"] {
            let ans = run("dig", &["+short", domain, rrtype], to);
            for line in ans.lines() {
                let ip = line.trim();
                // dig +short can emit CNAME lines too; keep only IP-looking ones
                if valid_ip(ip) && ip.contains(|c| c == '.' || c == ':') && !resolutions.iter().any(|r| r == ip) {
                    resolutions.push(ip.to_string());
                }
            }
        }
    }
    if !resolutions.is_empty() {
        // VT exposes these as last_dns_records; also surface a simple list.
        let recs: Vec<Value> = resolutions.iter().map(|ip| json!({
            "type": if ip.contains(':') { "AAAA" } else { "A" },
            "value": ip,
        })).collect();
        out.insert("last_dns_records".into(), json!(recs));
    }

    // ---- whois ----
    if tool_exists("whois") {
        let w = run("whois", &[domain], to);
        if !w.trim().is_empty() {
            out.insert("whois".into(), json!(w.trim()));
            // Pull a few structured fields VT also exposes, when present.
            if let Some(r) = whois_field(&w, &["Registrar:", "Registrar Name:", "Sponsoring Registrar:"]) {
                out.insert("registrar".into(), json!(r));
            }
            if let Some(d) = whois_field(&w, &["Creation Date:", "Created On:", "Registered on:", "Domain Registration Date:"]) {
                if let Some(ts) = parse_whois_epoch(&d) { out.insert("creation_date".into(), json!(ts)); }
            }
            if let Some(d) = whois_field(&w, &["Updated Date:", "Last Updated On:", "Last Modified:"]) {
                if let Some(ts) = parse_whois_epoch(&d) { out.insert("last_update_date".into(), json!(ts)); }
            }
            if let Some(d) = whois_field(&w, &["Registry Expiry Date:", "Expiration Date:", "Registrar Registration Expiration Date:"]) {
                if let Some(ts) = parse_whois_epoch(&d) { out.insert("expiration_date".into(), json!(ts)); }
            }
        }
    }

    // ---- TLS certificate over :443 (openssl s_client) ----
    if tool_exists("openssl") {
        if let Some(cert) = grab_tls_cert(domain, Some(domain)) {
            out.insert("last_https_certificate".into(), cert);
        }
    }

    out.insert("_source".into(), json!("host-analysis"));
    json!({ "attributes": Value::Object(out), "resolutions": resolutions })
}

/// Extract the first matching whois line value for any of the given labels.
fn whois_field(text: &str, labels: &[&str]) -> Option<String> {
    for line in text.lines() {
        let l = line.trim();
        for lab in labels {
            if l.len() > lab.len() && l[..lab.len()].eq_ignore_ascii_case(lab) {
                let v = l[lab.len()..].trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Parse a whois date (ISO-8601 or common variants) to epoch seconds. Best
/// effort: handles `YYYY-MM-DDTHH:MM:SS[Z]` and `YYYY-MM-DD`.
fn parse_whois_epoch(s: &str) -> Option<i64> {
    let s = s.trim();
    let digits: Vec<i64> = {
        // grab Y M D [H M S] from the leading part
        let cleaned: String = s.chars().map(|c| if c.is_ascii_digit() { c } else { ' ' }).collect();
        cleaned.split_whitespace().filter_map(|p| p.parse::<i64>().ok()).collect()
    };
    if digits.len() < 3 {
        return None;
    }
    let (y, mo, d) = (digits[0], digits[1], digits[2]);
    if y < 1970 || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let (hh, mm, ss) = (
        digits.get(3).copied().unwrap_or(0),
        digits.get(4).copied().unwrap_or(0),
        digits.get(5).copied().unwrap_or(0),
    );
    Some(ymd_to_epoch(y, mo, d, hh, mm, ss))
}

/// Days-from-civil algorithm (Howard Hinnant), to epoch seconds (UTC).
fn ymd_to_epoch(y: i64, m: i64, d: i64, hh: i64, mm: i64, ss: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + hh * 3600 + mm * 60 + ss
}

/// Grab the server's leaf TLS certificate via `openssl s_client` and parse a
/// few fields with `openssl x509`. Returns a VT-style `last_https_certificate`
/// object subset (subject/issuer/validity/serial/thumbprint) or None.
///
/// SECURITY: the host is passed ONLY as argv to `openssl` (-connect/-servername)
/// and the s_client→x509 pipe is wired with OS pipes (no shell). So there is no
/// shell metacharacter interpretation here at all — command injection is
/// structurally impossible regardless of what `host` contains, independent of
/// the upstream `valid_domain`/`valid_ip` checks (which still run, as defense in
/// depth).
///
/// `host` is the TCP connect target (a domain or an IP). `sni` is the optional
/// TLS servername (Some(domain) for domains; None for a bare IP, where SNI is
/// not meaningful and many servers present their default cert).
fn grab_tls_cert(host: &str, sni: Option<&str>) -> Option<Value> {
    let to = Duration::from_secs(30);
    let connect = format!("{host}:443");
    let mut s_client_args: Vec<&str> = vec!["s_client", "-connect", &connect];
    if let Some(name) = sni {
        s_client_args.push("-servername");
        s_client_args.push(name);
    }
    let txt = run_piped(
        ("openssl", &s_client_args),
        ("openssl", &["x509", "-noout", "-subject", "-issuer", "-serial", "-dates", "-fingerprint", "-sha256"]),
        to,
    );
    if txt.trim().is_empty() {
        return None;
    }
    let mut cert = Map::new();
    let mut subject = Map::new();
    let mut issuer = Map::new();
    for line in txt.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("subject=") {
            if let Some(cn) = rdn_value(v, "CN") { subject.insert("CN".into(), json!(cn)); }
            if let Some(o) = rdn_value(v, "O") { subject.insert("O".into(), json!(o)); }
        } else if let Some(v) = line.strip_prefix("issuer=") {
            if let Some(cn) = rdn_value(v, "CN") { issuer.insert("CN".into(), json!(cn)); }
            if let Some(o) = rdn_value(v, "O") { issuer.insert("O".into(), json!(o)); }
        } else if let Some(v) = line.strip_prefix("serial=") {
            cert.insert("serial_number".into(), json!(v.trim().to_lowercase()));
        } else if let Some(v) = line.strip_prefix("notBefore=") {
            cert.insert("validity_not_before".into(), json!(v.trim()));
        } else if let Some(v) = line.strip_prefix("notAfter=") {
            cert.insert("validity_not_after".into(), json!(v.trim()));
        } else if let Some(v) = line.strip_prefix("SHA256 Fingerprint=") {
            cert.insert("thumbprint_sha256".into(), json!(v.trim().replace(':', "").to_lowercase()));
        } else if let Some(v) = line.strip_prefix("sha256 Fingerprint=") {
            cert.insert("thumbprint_sha256".into(), json!(v.trim().replace(':', "").to_lowercase()));
        }
    }
    if !subject.is_empty() {
        cert.insert("subject".into(), Value::Object(subject));
    }
    if !issuer.is_empty() {
        cert.insert("issuer".into(), Value::Object(issuer));
    }
    if cert.is_empty() {
        None
    } else {
        Some(Value::Object(cert))
    }
}

/// Pull a single RDN value (e.g. CN) out of an openssl subject/issuer line like
/// `CN = example.com, O = Example Inc` or the older `/CN=…/O=…` format.
fn rdn_value(line: &str, key: &str) -> Option<String> {
    // new format: "CN = value, O = value"
    for part in line.split(',') {
        let p = part.trim();
        if let Some(rest) = p.strip_prefix(key) {
            let rest = rest.trim_start();
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v.trim().to_string());
            }
        }
    }
    // old format: "/CN=value/O=value"
    for part in line.split('/') {
        if let Some(rest) = part.strip_prefix(&format!("{key}=")) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/* ================================ IPs =================================== */

/// Analyze an IP: whois (netblock/org/ASN/country), the server's TLS certificate
/// grabbed the same way as for domains (openssl s_client | x509 over OS pipes —
/// no nmap involved), and an nmap full-port scan for open ports/services.
/// Returns `{ attributes: {...} }`.
pub fn analyze_ip(ip: &str) -> Value {
    if !valid_ip(ip) {
        return json!({"error": "invalid ip"});
    }
    let to = Duration::from_secs(CMD_TIMEOUT_SECS.max(300)); // full scan can be slow
    let mut out = Map::new();

    // ---- whois (netblock / org / ASN / country, when present) ----
    if tool_exists("whois") {
        let w = run("whois", &[ip], to);
        if !w.trim().is_empty() {
            out.insert("whois".into(), json!(w.trim()));
            if let Some(v) = whois_field(&w, &["NetRange:", "inetnum:", "CIDR:", "route:"]) {
                out.insert("network".into(), json!(v));
            }
            if let Some(v) = whois_field(&w, &["OrgName:", "org-name:", "Organization:", "owner:", "descr:", "netname:"]) {
                out.insert("as_owner".into(), json!(v));
            }
            if let Some(v) = whois_field(&w, &["OriginAS:", "origin:", "aut-num:"]) {
                out.insert("asn".into(), json!(v));
            }
            if let Some(v) = whois_field(&w, &["Country:", "country:"]) {
                out.insert("country".into(), json!(v));
            }
        }
    }

    // ---- TLS certificate (same method as domains: openssl, not nmap) ----
    // Connect to <ip>:443; no SNI for a bare IP. If the host serves TLS we get
    // its (default) certificate; otherwise this is silently skipped.
    if tool_exists("openssl") {
        if let Some(cert) = grab_tls_cert(ip, None) {
            out.insert("last_https_certificate".into(), cert);
        }
    }

    // ---- nmap full-port scan for open ports/services ----
    // NOTE: normal output (NOT -oG). The greppable format does not carry NSE
    // script output and parsed unreliably across nmap versions; normal output
    // lists ports as "443/tcp open https" which we parse directly. No --script
    // here — the certificate comes from openssl above.
    if tool_exists("nmap") {
        let v6 = if ip.contains(':') { vec!["-6"] } else { vec![] };
        let mut args: Vec<&str> = vec!["-Pn", "-p-", "--open"];
        args.extend(v6);
        args.push(ip);
        let txt = run("nmap", &args, to);

        let mut ports: Vec<u32> = Vec::new();
        let mut services: Vec<Value> = Vec::new();
        // Port rows look like: "443/tcp open  https" (state is the 2nd field).
        for raw in txt.lines() {
            let t = raw.trim();
            let mut it = t.split_whitespace();
            let portproto = match it.next() { Some(x) => x, None => continue };
            let state = it.next().unwrap_or("");
            if state != "open" { continue; }
            let (pnum, proto) = match portproto.split_once('/') {
                Some(x) => x, None => continue,
            };
            if let Ok(p) = pnum.parse::<u32>() {
                if !ports.contains(&p) { ports.push(p); }
                let svc = it.next().unwrap_or("");
                let mut s = Map::new();
                s.insert("port".into(), json!(p));
                s.insert("protocol".into(), json!(proto));
                if !svc.is_empty() { s.insert("service".into(), json!(svc)); }
                services.push(Value::Object(s));
            }
        }
        ports.sort_unstable();
        if !ports.is_empty() {
            let joined = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
            out.insert("open_ports".into(), json!(joined));
        }
        if !services.is_empty() {
            out.insert("services".into(), json!(services));
        }
    }

    if out.is_empty() {
        return json!({"error": "no data (whois/openssl/nmap unavailable or no response)"});
    }
    out.insert("_source".into(), json!("host-analysis"));
    json!({ "attributes": Value::Object(out) })
}

