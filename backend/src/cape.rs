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

//! CAPE sandbox REST client.
//!
//! IoCHub does not run or manage CAPE itself. The operator runs a CAPE instance
//! on their own host/VM and points IoCHub at it (url/token in `cape.conf`).
//! This module:
//!
//!   * drives detonations through CAPE's REST API (shelling out to `curl`),
//!   * tracks each detonation as an asynchronous job so the browser can walk
//!     away and come back, and
//!   * gates access with a per-user regex allow-list.
//!
//! Everything is driven by a small hand-editable config file, `cape.conf`, in
//! the data directory. It is re-read on every submit, so the access list and
//! the CAPE endpoint can be changed without restarting the service.
//!
//! Endpoints (see `main.rs`):
//!   POST /api/cape/submit   {sha256} | {filename,content_b64}  -> {job_id,status}
//!   GET  /api/cape/job/:id                                     -> {status, indicators?}

use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/* ============================== config ================================== */

pub struct Config {
    pub enabled: bool,
    pub url: String,
    pub token: Option<String>,
    pub insecure: bool,
    #[allow(dead_code)]
    pub startup_timeout: u64,
    #[allow(dead_code)]
    pub idle_timeout: u64,
    pub allow: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: true,
            url: "http://127.0.0.1:8000".to_string(),
            token: None,
            insecure: false,
            startup_timeout: 180,
            idle_timeout: 8 * 60 * 60,
            allow: vec![".*".to_string()],
        }
    }
}

impl Config {
    fn url_base(&self) -> String {
        self.url.trim_end_matches('/').to_string()
    }
    fn user_allowed(&self, user: &str) -> bool {
        for pat in &self.allow {
            let anchored = format!("^(?:{})$", pat);
            if let Ok(re) = Regex::new(&anchored) {
                if re.is_match(user) {
                    return true;
                }
            }
        }
        false
    }
}

/// Parse `cape.conf`. Unknown keys are ignored; missing file => defaults.
fn parse_config(text: &str) -> Config {
    let mut c = Config::default();
    let mut allow: Vec<String> = Vec::new();
    let mut in_allow = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_allow = line[1..line.len() - 1].trim().eq_ignore_ascii_case("allow");
            continue;
        }
        if in_allow {
            allow.push(line.to_string());
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            match k {
                "enabled" => c.enabled = is_true(v),
                "url" => {
                    if !v.is_empty() {
                        c.url = v.to_string();
                    }
                }
                "token" => c.token = if v.is_empty() { None } else { Some(v.to_string()) },
                "insecure" => c.insecure = is_true(v),
                "idle_timeout" => c.idle_timeout = v.parse().unwrap_or(c.idle_timeout),
                _ => {}
            }
        }
    }
    if !allow.is_empty() {
        c.allow = allow;
    }
    c
}

fn is_true(v: &str) -> bool {
    matches!(v, "1" | "true" | "yes" | "on") || v.eq_ignore_ascii_case("true")
}

/// The default config written on first run if none exists.
pub const DEFAULT_CONF: &str = r#"# IoCHub CAPE configuration.
#
# IoCHub drives an EXISTING CAPE instance over its REST API. You run and manage
# CAPE yourself (on its own host/VM); point IoCHub at it here. This file is
# re-read on every request, so changes take effect without restarting iochub.

# Master switch. CAPE is enabled by default; set to false to turn the
# "detonate (CAPE)" action off entirely.
enabled = true

# Where CAPE's REST API is reachable (e.g. the sandbox's private IPv4, or a
# localhost tunnel). Leave the default if you have not set up CAPE yet — the
# detonate action will simply report that CAPE is unreachable.
url = http://127.0.0.1:8000

# Optional CAPE API token (sent as "Authorization: Token <token>").
token =

# Set to 1 to accept a self-signed CAPE TLS certificate.
insecure = 0

# Users permitted to use CAPE. One regex per line below. Each is matched against
# the whole username. Default allows everyone; tighten this when ready, e.g.:
#   analyst-.*
#   ir-team
[allow]
.*
"#;

/* =============================== jobs =================================== */

#[derive(Clone)]
struct Job {
    status: String, // queued | running | reported | failed | not_found | error
    task_id: Option<i64>,
    #[allow(dead_code)]
    sha256: Option<String>,
    indicators: Option<Value>,
    detail: Option<String>,
    updated: u64,
}

impl Job {
    fn snapshot(&self) -> Value {
        let mut o = json!({ "status": self.status, "updated": self.updated });
        if let Some(t) = self.task_id {
            o["task_id"] = json!(t);
        }
        if let Some(ind) = &self.indicators {
            o["indicators"] = ind.clone();
        }
        if let Some(d) = &self.detail {
            o["detail"] = json!(d);
        }
        o
    }
}

/* ============================== manager ================================= */

pub struct Manager {
    data_dir: PathBuf,
    jobs: Mutex<HashMap<String, Job>>,
}

impl Manager {
    pub fn new(data_dir: &Path) -> Arc<Manager> {
        // Materialize a default config on first run so operators have something
        // to edit (and so the allow-list defaults to ".*").
        let conf = data_dir.join("cape.conf");
        if !conf.exists() {
            let _ = std::fs::write(&conf, DEFAULT_CONF);
        }
        Arc::new(Manager {
            data_dir: data_dir.to_path_buf(),
            jobs: Mutex::new(HashMap::new()),
        })
    }

    pub fn config(&self) -> Config {
        match std::fs::read_to_string(self.data_dir.join("cape.conf")) {
            Ok(t) => parse_config(&t),
            Err(_) => Config::default(),
        }
    }

    pub fn user_allowed(&self, cfg: &Config, user: &str) -> bool {
        cfg.user_allowed(user)
    }

    /// Submit a sample and return a job id immediately. A background thread polls
    /// CAPE to completion so the browser can leave and return.
    pub fn submit(self: &Arc<Self>, cfg: &Config, body: &Value) -> Value {
        if !cfg.enabled {
            return json!({"status":"disabled","detail":"CAPE is disabled (set enabled = true in cape.conf)."});
        }
        // IoCHub drives an operator-run CAPE over REST. If it isn't reachable,
        // report a soft "unconfigured" state with guidance rather than erroring.
        if !api_up(cfg) {
            return json!({"status":"unconfigured","detail": format!(
                "CAPE is not reachable at {}. Run a CAPE instance and set `url` (and `token`) \
                 in /opt/iochub/data/cape.conf to point IoCHub at it. See the CAPE section of the README.",
                cfg.url)});
        }

        // Kick off the submission (this part is quick: it returns a task id).
        let sub = if let Some(b64) = body.get("content_b64").and_then(|v| v.as_str()) {
            let name = body.get("filename").and_then(|v| v.as_str()).unwrap_or("sample.bin");
            submit_file(cfg, name, b64)
        } else if let Some(h) = body.get("sha256").and_then(|v| v.as_str()) {
            submit_hash(cfg, h)
        } else {
            return json!({"status":"error","detail":"provide sha256 or content_b64"});
        };

        let status = sub.get("status").and_then(|s| s.as_str()).unwrap_or("error");
        let task_id = sub.get("task_id").and_then(|t| t.as_i64());
        if status == "not_found" {
            return json!({"status":"not_found","detail":"no existing CAPE analysis for this hash — upload the file to detonate it."});
        }
        if task_id.is_none() {
            return json!({"status":"error","detail": sub.get("detail").cloned().unwrap_or(json!("CAPE returned no task id"))});
        }

        let job_id = rand_hex(8);
        let sha = body.get("sha256").and_then(|v| v.as_str()).map(|s| s.to_string());
        {
            let mut jobs = self.jobs.lock().unwrap();
            jobs.insert(
                job_id.clone(),
                Job { status: "running".into(), task_id, sha256: sha, indicators: None, detail: None, updated: now_secs() },
            );
        }
        // Background poller.
        let me = Arc::clone(self);
        let cfg2 = clone_cfg(cfg);
        let jid = job_id.clone();
        let tid = task_id.unwrap();
        std::thread::spawn(move || me.poll_job(jid, tid, cfg2));

        json!({"job_id": job_id, "status": "running", "task_id": task_id})
    }

    fn set_job<F: FnOnce(&mut Job)>(&self, id: &str, f: F) {
        if let Ok(mut jobs) = self.jobs.lock() {
            if let Some(j) = jobs.get_mut(id) {
                f(j);
                j.updated = now_secs();
            }
        }
    }

    fn poll_job(self: Arc<Self>, job_id: String, task_id: i64, cfg: Config) {
        let deadline = Instant::now() + Duration::from_secs(30 * 60); // cap a single wait
        loop {
            if Instant::now() > deadline {
                self.set_job(&job_id, |j| {
                    j.status = "error".into();
                    j.detail = Some("timed out waiting for CAPE report".into());
                });
                return;
            }
            std::thread::sleep(Duration::from_secs(5));
            let st = task_status(&cfg, task_id);
            match st.as_str() {
                "reported" | "completed" => {
                    let rep = fetch_report(&cfg, task_id);
                    match rep {
                        Ok(ind) => self.set_job(&job_id, |j| {
                            j.status = "reported".into();
                            j.indicators = Some(ind);
                        }),
                        Err(e) => self.set_job(&job_id, |j| {
                            j.status = "error".into();
                            j.detail = Some(e);
                        }),
                    }
                    return;
                }
                s if s.starts_with("fail") => {
                    self.set_job(&job_id, |j| {
                        j.status = "failed".into();
                        j.detail = Some(s.to_string());
                    });
                    return;
                }
                "__error__" => {
                    self.set_job(&job_id, |j| {
                        j.status = "error".into();
                        j.detail = Some("lost contact with CAPE".into());
                    });
                    return;
                }
                other => {
                    let other = other.to_string();
                    self.set_job(&job_id, |j| j.status = format!("running:{other}"));
                }
            }
        }
    }

    pub fn job(&self, id: &str) -> Value {
        match self.jobs.lock().unwrap().get(id) {
            Some(j) => j.snapshot(),
            None => json!({"status":"unknown","detail":"no such job (the backend may have restarted) — re-detonate."}),
        }
    }
}

fn clone_cfg(c: &Config) -> Config {
    Config {
        enabled: c.enabled,
        url: c.url.clone(),
        token: c.token.clone(),
        insecure: c.insecure,
        startup_timeout: c.startup_timeout,
        idle_timeout: c.idle_timeout,
        allow: c.allow.clone(),
    }
}

/* ============================ REST plumbing ============================= */

fn tmp_path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("iochub-cape-{tag}-{}", rand_hex(8)));
    p
}

/// Run a prepared curl command, feeding the optional auth header on stdin so the
/// token never appears in argv or process listings. Returns the HTTP code.
fn run_curl(cfg: &Config, mut cmd: Command) -> Result<u16, String> {
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("failed to launch curl: {e}"))?;
    {
        let stdin = child.stdin.as_mut().ok_or("no curl stdin")?;
        let cfgline = match &cfg.token {
            Some(t) => format!("header = \"Authorization: Token {t}\"\n"),
            None => String::new(),
        };
        stdin.write_all(cfgline.as_bytes()).map_err(|e| format!("curl stdin: {e}"))?;
    }
    let out = child.wait_with_output().map_err(|e| format!("curl wait: {e}"))?;
    let code: u16 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0);
    if code == 0 {
        return Err(format!("CAPE transport error: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(code)
}

fn curl_get(cfg: &Config, url: &str, out: &Path, max_time: u32) -> Result<u16, String> {
    let mut cmd = Command::new("curl");
    cmd.arg("-sS").arg("--max-time").arg(max_time.to_string());
    if cfg.insecure {
        cmd.arg("-k");
    }
    cmd.arg("-o").arg(out).arg("-w").arg("%{http_code}").arg("-K").arg("-").arg(url);
    run_curl(cfg, cmd)
}

fn read_json(path: &Path, max: u64) -> Result<Value, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("read: {e}"))?;
    if meta.len() > max {
        return Err(format!("CAPE response too large ({} bytes)", meta.len()));
    }
    let txt = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(&txt).map_err(|e| format!("CAPE returned non-JSON: {e}"))
}

/// Is the CAPE API answering at all? Any HTTP status (even 404) means "up".
fn api_up(cfg: &Config) -> bool {
    let url = format!("{}/apiv2/", cfg.url_base());
    let out = tmp_path("ping");
    let r = curl_get(cfg, &url, &out, 4);
    let _ = std::fs::remove_file(&out);
    matches!(r, Ok(code) if code != 0)
}

fn hash_field(h: &str) -> &'static str {
    match h.len() {
        32 => "md5",
        40 => "sha1",
        _ => "sha256",
    }
}

fn submit_hash(cfg: &Config, hash: &str) -> Value {
    if hash.len() < 32 || !hash.chars().all(|x| x.is_ascii_alphanumeric()) {
        return json!({"status":"error","detail":"bad hash"});
    }
    let url = format!("{}/apiv2/tasks/search/{}/{}/", cfg.url_base(), hash_field(hash), hash);
    let out = tmp_path("search");
    let parsed = curl_get(cfg, &url, &out, 30).and_then(|code| read_json(&out, 8 * 1024 * 1024).map(|v| (code, v)));
    let _ = std::fs::remove_file(&out);
    match parsed {
        Ok((code, v)) => {
            if code >= 400 {
                return json!({"status":"error","detail":format!("CAPE search HTTP {code}")});
            }
            let id = v
                .get("data")
                .and_then(|d| d.as_array())
                .and_then(|arr| arr.iter().filter_map(|t| t.get("id").and_then(|i| i.as_i64())).max());
            match id {
                Some(id) => json!({"status":"found","task_id":id}),
                None => json!({"status":"not_found"}),
            }
        }
        Err(e) => json!({"status":"error","detail":e}),
    }
}

fn submit_file(cfg: &Config, name: &str, b64: &str) -> Value {
    let bytes = match b64_decode(b64) {
        Ok(b) => b,
        Err(e) => return json!({"status":"error","detail":e}),
    };
    let tmp = tmp_path("upload");
    if let Err(e) = std::fs::write(&tmp, &bytes) {
        return json!({"status":"error","detail":format!("temp write: {e}")});
    }
    let url = format!("{}/apiv2/tasks/create/file/", cfg.url_base());
    let field = format!("file=@{};filename={}", tmp.display(), sanitize(name));
    let out = tmp_path("submit");

    let mut cmd = Command::new("curl");
    cmd.arg("-sS").arg("--max-time").arg("300");
    if cfg.insecure {
        cmd.arg("-k");
    }
    cmd.arg("-o").arg(&out).arg("-w").arg("%{http_code}").arg("-K").arg("-");
    cmd.arg("-F").arg(&field).arg(&url);

    let parsed = run_curl(cfg, cmd).and_then(|code| read_json(&out, 4 * 1024 * 1024).map(|v| (code, v)));
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(&out);
    match parsed {
        Ok((code, v)) => {
            if code >= 400 {
                return json!({"status":"error","detail":format!("CAPE submit HTTP {code}")});
            }
            let id = v
                .pointer("/data/task_ids/0")
                .and_then(|i| i.as_i64())
                .or_else(|| v.pointer("/data/task_id").and_then(|i| i.as_i64()))
                .or_else(|| v.get("task_id").and_then(|i| i.as_i64()))
                .or_else(|| v.pointer("/data/0").and_then(|i| i.as_i64()));
            match id {
                Some(id) => json!({"status":"submitted","task_id":id}),
                None => json!({"status":"error","detail":"CAPE accepted upload but returned no task id"}),
            }
        }
        Err(e) => json!({"status":"error","detail":e}),
    }
}

/// Returns the CAPE status string, or "__error__" if the call itself failed.
fn task_status(cfg: &Config, id: i64) -> String {
    let url = format!("{}/apiv2/tasks/status/{}/", cfg.url_base(), id);
    let out = tmp_path("status");
    let parsed = curl_get(cfg, &url, &out, 20).and_then(|code| read_json(&out, 1024 * 1024).map(|v| (code, v)));
    let _ = std::fs::remove_file(&out);
    match parsed {
        Ok((code, v)) => {
            if code >= 400 {
                return "__error__".into();
            }
            v.get("data").and_then(|d| d.as_str()).unwrap_or("unknown").to_string()
        }
        Err(_) => "__error__".into(),
    }
}

fn fetch_report(cfg: &Config, id: i64) -> Result<Value, String> {
    let url = format!("{}/apiv2/tasks/get/report/{}/json/", cfg.url_base(), id);
    let out = tmp_path("report");
    let parsed = curl_get(cfg, &url, &out, 120).and_then(|code| read_json(&out, 96 * 1024 * 1024).map(|v| (code, v)));
    let _ = std::fs::remove_file(&out);
    match parsed {
        Ok((code, v)) => {
            if code >= 400 {
                Err(format!("CAPE report HTTP {code}"))
            } else {
                Ok(extract_iocs(&v))
            }
        }
        Err(e) => Err(e),
    }
}

/* ============================== extraction ============================== */

fn push(v: &mut Vec<String>, s: &str) {
    let s = s.trim();
    if !s.is_empty() && !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

fn collect_dropped(dst: &mut Vec<Value>, arr: &[Value]) {
    for f in arr {
        if let Some(sha) = f.get("sha256").and_then(|x| x.as_str()) {
            let name = f
                .get("name")
                .and_then(|x| x.as_str())
                .or_else(|| f.get("filepath").and_then(|x| x.as_str()))
                .map(|s| s.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(s).to_string());
            dst.push(json!({"sha256": sha, "name": name}));
        }
    }
}

/// Pull network + dropped IoCs out of a CAPE JSON report, defensively (report
/// shapes vary across CAPE versions).
fn extract_iocs(report: &Value) -> Value {
    let mut domains: Vec<String> = Vec::new();
    let mut ips: Vec<String> = Vec::new();
    let mut urls: Vec<String> = Vec::new();
    let mut dropped: Vec<Value> = Vec::new();

    if let Some(net) = report.get("network") {
        if let Some(arr) = net.get("domains").and_then(|d| d.as_array()) {
            for d in arr {
                if let Some(dom) = d.get("domain").and_then(|x| x.as_str()) {
                    push(&mut domains, dom);
                }
                if let Some(ip) = d.get("ip").and_then(|x| x.as_str()) {
                    push(&mut ips, ip);
                }
            }
        }
        if let Some(arr) = net.get("hosts").and_then(|d| d.as_array()) {
            for h in arr {
                if let Some(ip) = h.as_str() {
                    push(&mut ips, ip);
                } else if let Some(ip) = h.get("ip").and_then(|x| x.as_str()) {
                    push(&mut ips, ip);
                }
            }
        }
        for key in ["http", "http_ex", "https_ex"] {
            if let Some(arr) = net.get(key).and_then(|d| d.as_array()) {
                for r in arr {
                    let uri = r.get("uri").and_then(|x| x.as_str());
                    let url = r.get("url").and_then(|x| x.as_str());
                    let host = r.get("host").and_then(|x| x.as_str());
                    if let Some(u) = url {
                        push(&mut urls, u);
                    } else if let Some(u) = uri.filter(|s| s.starts_with("http")) {
                        push(&mut urls, u);
                    } else if let (Some(h), Some(u)) = (host, uri) {
                        push(&mut urls, &format!("http://{h}{u}"));
                    }
                    if let Some(h) = host {
                        push(&mut domains, h);
                    }
                }
            }
        }
        for key in ["tcp", "udp"] {
            if let Some(arr) = net.get(key).and_then(|d| d.as_array()) {
                for r in arr {
                    if let Some(dst) = r.get("dst").and_then(|x| x.as_str()) {
                        push(&mut ips, dst);
                    }
                }
            }
        }
    }

    if let Some(arr) = report.get("dropped").and_then(|d| d.as_array()) {
        collect_dropped(&mut dropped, arr);
    }
    if let Some(arr) = report.pointer("/CAPE/payloads").and_then(|d| d.as_array()) {
        collect_dropped(&mut dropped, arr);
    }

    domains.retain(|d| d.contains('.') && d.chars().any(|c| c.is_ascii_alphabetic()));

    json!({"domains": domains, "ips": ips, "urls": urls, "dropped": dropped})
}

/* ================================ utils ================================= */

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn rand_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    let _ = getrandom::getrandom(&mut b);
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn sanitize(name: &str) -> String {
    let base = name.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(name);
    let s: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    if s.is_empty() {
        "sample.bin".to_string()
    } else {
        s
    }
}

/// Minimal base64 decoder (avoids pulling an extra crate).
fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = val(c).ok_or("invalid base64")?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}
