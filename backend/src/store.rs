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

//! File-backed persistence. Users live in a single JSON file; each graph slot
//! is its own JSON file so it can be downloaded/replaced wholesale. All access
//! is serialized through a `Mutex` held in `AppState`.
//!
//! Permanence intentionally takes a back seat to simplicity (per spec): this is
//! plain JSON on disk, not a database.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Maximum graph slots per user. Slots 1 and 2 are the user's two manual
/// graphs (spec: "limit it to two graphs for now"); slot 3 is reserved for the
/// automatic autosave snapshot, which the frontend manages separately (the
/// backend treats all three identically — it's just storage).
pub const MAX_SLOTS: u8 = 3;

#[derive(Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub username: String,
    /// PHC-format Argon2id hash string (of the client-derived auth secret).
    /// For Entra/SSO accounts that haven't set a passphrase this may be empty.
    #[serde(default)]
    pub pw_hash: String,
    pub created: u64,
    /// Admins are the only accounts allowed to create other accounts.
    #[serde(default)]
    pub is_admin: bool,
    /// How this account authenticates: "local" (password, zero-knowledge) or
    /// "entra" (Entra ID SSO). Defaults to local for existing records.
    #[serde(default = "default_auth_source")]
    pub auth_source: String,
    /// For SSO accounts in server-side-encryption mode (option A): a base64
    /// server-held key the backend uses to encrypt/decrypt this user's content.
    /// Present ONLY while the SSO user has not set their own passphrase. When
    /// they "add a graph passphrase" (upgrade to zero-knowledge / option B),
    /// this is cleared and content is re-encrypted under the browser key.
    /// SECURITY: while set, the server (and host/directory admins) can read the
    /// user's graphs. Local-password users never have this.
    #[serde(default)]
    pub server_key_b64: Option<String>,
    /// The Entra object id (oid) bound to this SSO account, if any.
    #[serde(default)]
    pub entra_oid: Option<String>,
}
fn default_auth_source() -> String { "local".to_string() }

#[derive(Default, Serialize, Deserialize)]
pub struct UsersFile {
    pub users: HashMap<String, UserRecord>,
}

/// One logged VT query that an analyst hand-edited away from the auto-built
/// query. Persisted server-side so admins can review how analysts refine
/// queries (e.g. better facet mappings). Stored append-only.
#[derive(Clone, Serialize, Deserialize)]
pub struct QueryLogEntry {
    pub ts: u64,
    pub username: String,
    /// The final query the analyst actually ran.
    pub final_query: String,
    /// The query IoCHub auto-generated before the edit.
    #[serde(default)]
    pub auto_query: String,
    /// The attribute paths the auto-query was built from.
    #[serde(default)]
    pub attributes: Vec<String>,
}

/// On-disk paths and the serialized user table.
pub struct Store {
    graphs_dir: PathBuf,
    users_path: PathBuf,
    query_log_path: PathBuf,
    users: UsersFile,
}

impl Store {
    /// Open (or initialize) the store rooted at `data_dir`.
    pub fn open(data_dir: &str) -> std::io::Result<Self> {
        let data_dir = PathBuf::from(data_dir);
        let graphs_dir = data_dir.join("graphs");
        fs::create_dir_all(&graphs_dir)?;
        let users_path = data_dir.join("users.json");
        let query_log_path = data_dir.join("query_log.json");
        let users = if users_path.exists() {
            let txt = fs::read_to_string(&users_path)?;
            serde_json::from_str(&txt).unwrap_or_default()
        } else {
            UsersFile::default()
        };
        Ok(Store { graphs_dir, users_path, query_log_path, users })
    }

    fn persist_users(&self) -> std::io::Result<()> {
        let txt = serde_json::to_string_pretty(&self.users).unwrap_or_else(|_| "{}".into());
        write_atomic(&self.users_path, txt.as_bytes())
    }

    pub fn user_exists(&self, username: &str) -> bool {
        self.users.users.contains_key(username)
    }

    pub fn get_user(&self, username: &str) -> Option<UserRecord> {
        self.users.users.get(username).cloned()
    }

    pub fn insert_user(&mut self, rec: UserRecord) -> std::io::Result<()> {
        self.users.users.insert(rec.username.clone(), rec);
        self.persist_users()
    }

    /// Replace a user's stored password hash (used by change-password).
    pub fn update_password(&mut self, username: &str, new_hash: &str) -> std::io::Result<()> {
        if let Some(r) = self.users.users.get_mut(username) {
            r.pw_hash = new_hash.to_string();
        }
        self.persist_users()
    }

    /// Sanitize a username into a safe filename component (no path escape).
    fn safe_name(username: &str) -> String {
        username
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect()
    }

    /// Per-user, per-slot graph file path: `graphs/<user>__<slot>.json`.
    fn graph_path(&self, username: &str, slot: u8) -> PathBuf {
        self.graphs_dir.join(format!("{}__{slot}.json", Self::safe_name(username)))
    }

    /// Per-user encrypted VT-key blob path.
    fn vt_path(&self, username: &str) -> PathBuf {
        self.graphs_dir.join(format!("{}__vtkey.json", Self::safe_name(username)))
    }

    /// Read the encrypted VT-key blob (opaque ciphertext envelope), if any.
    pub fn read_vt(&self, username: &str) -> Option<String> {
        fs::read_to_string(self.vt_path(username)).ok()
    }
    /// Overwrite the encrypted VT-key blob.
    pub fn write_vt(&self, username: &str, json: &str) -> std::io::Result<()> {
        write_atomic(&self.vt_path(username), json.as_bytes())
    }
    /// Remove the stored VT-key blob.
    pub fn delete_vt(&self, username: &str) {
        let _ = fs::remove_file(self.vt_path(username));
    }

    fn misp_path(&self, username: &str) -> PathBuf {
        self.graphs_dir.join(format!("{}__mispkey.json", Self::safe_name(username)))
    }
    /// Read the encrypted MISP-key blob (opaque ciphertext envelope), if any.
    pub fn read_misp(&self, username: &str) -> Option<String> {
        fs::read_to_string(self.misp_path(username)).ok()
    }
    /// Overwrite the encrypted MISP-key blob.
    pub fn write_misp(&self, username: &str, json: &str) -> std::io::Result<()> {
        write_atomic(&self.misp_path(username), json.as_bytes())
    }
    /// Remove the stored MISP-key blob.
    pub fn delete_misp(&self, username: &str) {
        let _ = fs::remove_file(self.misp_path(username));
    }

    /// Maximum query-log entries retained on disk (oldest dropped beyond this).
    const QUERY_LOG_CAP: usize = 5000;

    /// Read all logged queries (newest last). Tolerant of a missing/corrupt file.
    pub fn read_query_log(&self) -> Vec<QueryLogEntry> {
        match fs::read_to_string(&self.query_log_path) {
            Ok(txt) => serde_json::from_str(&txt).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }
    /// Append one query-log entry, capping total retained entries.
    pub fn append_query_log(&self, entry: QueryLogEntry) -> std::io::Result<()> {
        let mut all = self.read_query_log();
        all.push(entry);
        let len = all.len();
        if len > Self::QUERY_LOG_CAP {
            all.drain(0..len - Self::QUERY_LOG_CAP);
        }
        let txt = serde_json::to_string(&all).unwrap_or_else(|_| "[]".into());
        write_atomic(&self.query_log_path, txt.as_bytes())
    }

    /// Read a graph slot's raw JSON, or `None` if empty/unsaved.
    pub fn read_graph(&self, username: &str, slot: u8) -> Option<String> {
        let p = self.graph_path(username, slot);
        fs::read_to_string(p).ok()
    }

    /// Overwrite a graph slot with raw JSON text.
    pub fn write_graph(&self, username: &str, slot: u8, json: &str) -> std::io::Result<()> {
        let p = self.graph_path(username, slot);
        write_atomic(&p, json.as_bytes())
    }

    /// Which slots (1..=MAX_SLOTS) currently hold a saved graph.
    pub fn list_slots(&self, username: &str) -> Vec<u8> {
        (1..=MAX_SLOTS).filter(|s| self.graph_path(username, *s).exists()).collect()
    }
}

/// Write a file atomically: write to a temp sibling then rename into place.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
    }
    fs::rename(&tmp, path)
}

/// Shared application state guarded by a single mutex.
pub struct AppState {
    pub store: Mutex<Store>,
    pub auth: Mutex<crate::auth::Auth>,
    pub public_dir: PathBuf,
    pub cape: std::sync::Arc<crate::cape::Manager>,
}
