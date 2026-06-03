/*
 * IoCHub — Indicator-of-Compromise graph platform
 * Copyright (C) 2026 vmarik
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. This program is distributed WITHOUT ANY WARRANTY; see the
 * GNU General Public License for more details. You should have received a copy
 * of the License along with this program (see the LICENSE file); if not, see
 * <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/* =========================================================================
   IoCHub — front-end application
   Everything VT-related runs in the browser. Keys live in the browser only.
   ========================================================================= */
'use strict';

/* ----------------------------- VT metadata ------------------------------ */
const KIND = {
  file:   { vt: 'files',        glyph: '⬢', label: 'file'   },
  domain: { vt: 'domains',      glyph: '◉', label: 'domain' },
  ip:     { vt: 'ip_addresses', glyph: '▣', label: 'ip'     },
  url:    { vt: 'urls',         glyph: '↗', label: 'url'    },
};

// VT relationship name -> kind it yields (null = not a graphable entity / handled specially)
const REL_TARGET = {
  resolutions: 'resolution',                 // special: domain<->ip
  communicating_files: 'file', downloaded_files: 'file', referrer_files: 'file',
  bundled_files: 'file', dropped_files: 'file', execution_parents: 'file',
  compressed_parents: 'file', similar_files: 'file',
  contacted_domains: 'domain', embedded_domains: 'domain', subdomains: 'domain',
  siblings: 'domain', immediate_parent: 'domain', parent: 'domain',
  contacted_ips: 'ip', embedded_ips: 'ip', last_serving_ip_address: 'ip',
  contacted_urls: 'url', embedded_urls: 'url', itw_urls: 'url', urls: 'url',
  redirecting_urls: 'url', redirects_to: 'url',
  historical_whois: null, historical_ssl_certificates: null,
  behaviours: null, network_location: null,
};

const RELS = {
  file:   ['contacted_domains','contacted_ips','contacted_urls','embedded_domains',
           'embedded_ips','embedded_urls','itw_urls','bundled_files','dropped_files',
           'execution_parents','compressed_parents','similar_files','behaviours'],
  domain: ['resolutions','communicating_files','downloaded_files','referrer_files',
           'urls','subdomains','siblings','immediate_parent','parent',
           'historical_whois','historical_ssl_certificates'],
  ip:     ['resolutions','communicating_files','downloaded_files','referrer_files',
           'urls','historical_whois','historical_ssl_certificates'],
  url:    ['contacted_domains','contacted_ips','downloaded_files','communicating_files',
           'redirecting_urls','redirects_to','last_serving_ip_address','network_location'],
};

// Fields that, when added to graph, default to SUB-ENTITIES (mere attributes)
const DEFAULT_SUB_FIELDS = [
  'registrar','as_owner','asn','country','continent','network','jarm','tld',
  'reputation','creation_date','last_modification_date','last_update_date',
  'registration_date','expiration_date','whois','whois_date','categories',
  'last_analysis_stats.malicious','last_analysis_stats.suspicious',
  'meaningful_name','type_description','type_tag','magic','ssdeep','tlsh',
  'first_submission_date','last_submission_date','times_submitted',
];

/* ------------------------- autopivot configuration ----------------------
   Per entity type: a false-positive `sensitivity` (max hit count; results with
   MORE hits than this are treated as too-common and not added) and a list of
   attribute `rules`. Each rule AND-combines one or more `parts`; a part names a
   directly-queryable attribute, the VT search `facet` it maps to, and a regex
   whose first capturing group is extracted from that attribute's value on the
   source entity and used as the search term. `depth` controls how many
   expansion passes the engine makes over the graph. All of this is editable in
   Settings → autopivot, and persists in localStorage. */
const DEFAULT_AUTOPIVOT = {
  depth: 2,
  types: {
    domain: {
      sensitivity: 30,
      rules: [
        { enabled: false, name: 'registrar + whois Updated Date',
          parts: [
            { attr: 'whois', facet: 'whois', regex: 'Updated Date:\\s*(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})' },
            { attr: 'registrar', facet: 'registrar', regex: '(.+)' },
          ] },
      ],
    },
    ip: { sensitivity: 30, rules: [] },
    url: { sensitivity: 30, rules: [] },
    file: {
      sensitivity: 30,
      rules: [
        { enabled: true, name: 'same signing certificate (serial)',
          parts: [ { attr: 'signature_info.x509[0].serial number', facet: 'signature:serial', regex: '(.+)' } ] },
        { enabled: true, name: 'same ssdeep',
          parts: [ { attr: 'ssdeep', facet: 'ssdeep', regex: '(.+)' } ] },
      ],
    },
  },
};

/* ------------------------------- state ---------------------------------- */
const state = {
  G: blankGraph(),
  settings: {
    theme: 'night', accent: '#c8702a',
    backendUrl: '', showSubs: true, subFields: DEFAULT_SUB_FIELDS.slice(),
    autopivot: null,   // populated from DEFAULT_AUTOPIVOT on first load (see below)
    mispUrl: '', mispAutoEnrich: false,
  },
  vtKey: '',
  mispKey: '',
  token: '', user: '', isAdmin: false,
  authSource: 'local', serverSideEnc: false,
  encKey: null,            // in-memory AES-GCM CryptoKey derived from the password
  calls: 0,
  activeSlot: null,
  cy: null,
  drawerEntity: null,
  multiMode: false, multiIds: null,
  selectMode: false,
};

function blankGraph() {
  return { meta: { created: Date.now(), name: 'untitled' },
           entities: {}, subs: {}, edges: {} };
}

/* ----------------------------- tiny utils ------------------------------- */
const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

// Mix two hex colours; t=0 → a, t=1 → b. Used for the "task running" halo
// (accent pushed halfway to the graph background). Tolerates #rgb / #rrggbb and
// falls back to `a` if a colour can't be parsed.
function mixHex(a, b, t = 0.5) {
  const parse = (c) => {
    if (typeof c !== 'string') return null;
    let h = c.trim().replace(/^#/, '');
    if (h.length === 3) h = h.split('').map(x => x + x).join('');
    if (!/^[0-9a-fA-F]{6}$/.test(h)) return null;
    return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
  };
  const ca = parse(a), cb = parse(b);
  if (!ca || !cb) return a;
  const m = ca.map((v, i) => Math.round(v + (cb[i] - v) * t));
  return '#' + m.map(v => v.toString(16).padStart(2, '0')).join('');
}
const el = (t, a = {}, kids = []) => {
  const n = document.createElement(t);
  // boolean HTML attributes are toggled by PRESENCE, so a literal `false` must
  // NOT set them (e.g. disabled:false would otherwise still disable the node).
  const BOOL_ATTR = { disabled: 1, checked: 1, readonly: 1, multiple: 1, selected: 1, required: 1, hidden: 1, open: 1 };
  for (const k in a) {
    if (k === 'class') n.className = a[k];
    else if (k === 'html') n.innerHTML = a[k];
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), a[k]);
    else if (BOOL_ATTR[k]) { if (a[k]) n.setAttribute(k, ''); }   // set only when truthy
    else if (a[k] != null) n.setAttribute(k, a[k]);
  }
  (Array.isArray(kids) ? kids : [kids]).forEach(c =>
    c != null && n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c));
  return n;
};
const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const uid = p => p + '_' + Math.random().toString(36).slice(2, 9);
const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const cssEsc = s => (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/["\\\]]/g, '\\$&');
function bufToB64(buf) {
  const bytes = new Uint8Array(buf); let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk)
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  return btoa(bin);
}

function toast(msg, err = false) {
  const t = el('div', { class: 'toast' + (err ? ' err' : ''), html: esc(msg) });
  $('#toasts').appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 250); }, err ? 5200 : 3200);
}
function busy(on, msg = '') {
  $('#busy').innerHTML = on ? `<span class="spin"></span> ${esc(msg)}` : '';
}

/* ============================ task log ================================= */
// A per-session log of operations the user ran (enrich, static, CAPE, pivot,
// graph save, …). Each task records a start time and shows a spinning gear
// while running; on completion the row shows a green check (and the timestamp
// is replaced by the END time) or a red cross on failure. Running tasks sort to
// the bottom; finished tasks are newest-last above them.
state.tasks = state.tasks || [];
let _taskSeq = 0;
const GEAR_SVG = '<svg class="gear" viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">'
  + '<path fill="currentColor" d="M8 5.2A2.8 2.8 0 1 0 8 10.8 2.8 2.8 0 0 0 8 5.2zm0 1.5a1.3 1.3 0 1 1 0 2.6 1.3 1.3 0 0 1 0-2.6z"/>'
  + '<path fill="currentColor" d="M7.1.8h1.8l.3 1.7c.5.13.97.33 1.4.6l1.5-.9 1.27 1.27-.9 1.5c.27.43.47.9.6 1.4l1.7.3v1.8l-1.7.3c-.13.5-.33.97-.6 1.4l.9 1.5-1.27 1.27-1.5-.9c-.43.27-.9.47-1.4.6l-.3 1.7H7.1l-.3-1.7a4.8 4.8 0 0 1-1.4-.6l-1.5.9-1.27-1.27.9-1.5a4.8 4.8 0 0 1-.6-1.4L1.23 8.9V7.1l1.7-.3c.13-.5.33-.97.6-1.4l-.9-1.5L3.9 2.63l1.5.9c.43-.27.9-.47 1.4-.6z"/></svg>';

function isoLocal(ms) {
  const d = new Date(ms);
  const pad = n => String(n).padStart(2, '0');
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? '+' : '-';
  const oh = pad(Math.floor(Math.abs(off) / 60)), om = pad(Math.abs(off) % 60);
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}${sign}${oh}:${om}`;
}
function renderTasks() {
  const log = $('#taskLog'); if (!log) return;
  const done = state.tasks.filter(t => t.status !== 'running');
  const running = state.tasks.filter(t => t.status === 'running');
  const ordered = [...done, ...running];   // running pinned at the bottom
  log.innerHTML = '';
  if (!ordered.length) { log.appendChild(el('div', { class: 'empty' }, 'no tasks yet')); return; }
  ordered.forEach(t => {
    let ico;
    if (t.status === 'running') ico = el('span', { class: 'tk-ico', html: GEAR_SVG });
    else if (t.status === 'done') ico = el('span', { class: 'tk-ico tk-done' }, '✔');
    else ico = el('span', { class: 'tk-ico tk-fail' }, '✘');
    const stamp = t.status === 'running' ? t.start : (t.end || t.start);  // END time once finished
    const row = el('div', { class: 'task-row ' + (t.status === 'running' ? 'run' : t.status) }, [
      ico,
      el('span', { class: 'ts' }, isoLocal(stamp)),
      el('span', { class: 'tt' }, t.type),
      el('span', { class: 'tr' }, t.result || ''),
    ]);
    log.appendChild(row);
  });
  const b = $('#btnTasks');
  if (b) b.textContent = running.length ? `tasks (${running.length})` : 'tasks';
}
// Track how many running tasks touch each node so the halo only clears when the
// last one finishes (an entity can have e.g. enrich + static at once).
const _nodeTaskCount = {};
function _nodeTaskInc(nodeId) {
  if (!nodeId || !state.cy) return;
  _nodeTaskCount[nodeId] = (_nodeTaskCount[nodeId] || 0) + 1;
  state.cy.$id(nodeId).addClass('task-running');
}
function _nodeTaskDec(nodeId) {
  if (!nodeId || !state.cy) return;
  _nodeTaskCount[nodeId] = Math.max(0, (_nodeTaskCount[nodeId] || 0) - 1);
  if (_nodeTaskCount[nodeId] === 0) state.cy.$id(nodeId).removeClass('task-running');
}
function startTask(type, detail = '', nodeId = null) {
  const t = { id: ++_taskSeq, type, result: detail, status: 'running', start: Date.now(), end: null };
  state.tasks.push(t);
  renderTasks();
  _nodeTaskInc(nodeId);
  let cleared = false;
  const clear = () => { if (!cleared) { cleared = true; _nodeTaskDec(nodeId); } };
  return {
    done: (result) => { t.status = 'done'; t.end = Date.now(); if (result != null) t.result = result; clear(); renderTasks(); },
    fail: (result) => { t.status = 'fail'; t.end = Date.now(); if (result != null) t.result = result; clear(); renderTasks(); },
    update: (result) => { t.result = result; renderTasks(); },
  };
}

// Record a VT query that the analyst hand-edited away from the auto-built one.
// We keep a structured list (state.queryEdits) — useful for refining facet
// mappings later — and drop a finished row into the task log so it's visible.
// Logs the final query, the original auto-query, and the source attributes.
state.queryEdits = state.queryEdits || [];
function logEditedQuery(finalQuery, autoQuery, sourceAttrs) {
  const rec = { ts: Date.now(), final: finalQuery, auto: autoQuery, attributes: (sourceAttrs || []).slice() };
  state.queryEdits.push(rec);
  const h = startTask('vt-query (edited)', `${(sourceAttrs || []).join(', ') || 'no attrs'} → ${finalQuery}`);
  h.done(finalQuery);
  // Persist server-side (best-effort; admins can review). Requires a session.
  if (state.token) {
    apiCall('/api/query_log', { method: 'POST',
      body: { final: finalQuery, auto: autoQuery, attributes: rec.attributes } })
      .catch(() => {/* non-fatal: it's still in the in-memory list + task log */});
  }
}

function flatten(obj, prefix = '', out = {}) {
  if (obj === null || obj === undefined) { out[prefix] = obj; return out; }
  if (Array.isArray(obj)) {
    if (obj.length === 0) { out[prefix] = '[]'; return out; }
    obj.forEach((v, i) => flatten(v, prefix ? `${prefix}[${i}]` : `[${i}]`, out));
  } else if (typeof obj === 'object') {
    const keys = Object.keys(obj);
    if (keys.length === 0) { out[prefix] = '{}'; return out; }
    keys.forEach(k => flatten(obj[k], prefix ? `${prefix}.${k}` : k, out));
  } else { out[prefix] = obj; }
  return out;
}

/* --------------------------- indicator typing --------------------------- */
function detectKind(v) {
  v = v.trim();
  if (/^https?:\/\//i.test(v)) return 'url';
  if (/^[a-f0-9]{64}$/i.test(v) || /^[a-f0-9]{40}$/i.test(v) || /^[a-f0-9]{32}$/i.test(v)) return 'file';
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ip';
  if (/^[0-9a-f:]+:[0-9a-f:]+$/i.test(v) && v.includes(':')) return 'ip';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return 'domain';
  return null;
}
function looksLikeIoC(v) {
  if (typeof v !== 'string') return null;
  return detectKind(v);
}
function b64urlUrl(u) {
  return btoa(unescape(encodeURIComponent(u))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// VirusTotal reports a file's real type in type_extension / type_tag /
// type_description; its meaningful_name is just one of many submission names and
// often carries a different extension than the actual file type. Derive the real
// type and a display name whose extension matches it, instead of trusting the
// name's extension blindly.
const EXEC_EXTS = ['exe','dll','sys','scr','com','msi','bat','cmd','ps1','vbs','js','jar','elf','so'];
function fileType(a) {
  a = a || {};
  if (a.type_extension) return String(a.type_extension).toLowerCase();
  const tag = String(a.type_tag || '').toLowerCase();
  if (tag === 'peexe') return 'exe';
  if (tag === 'pedll') return 'dll';
  const td = String(a.type_description || '').toLowerCase();
  for (const e of EXEC_EXTS) if (new RegExp('\\b' + e + '\\b').test(td)) return e;
  return null;
}
function fileDisplayName(a, id) {
  a = a || {};
  const ext = fileType(a);
  const names = Array.isArray(a.names) ? a.names.filter(n => typeof n === 'string') : [];
  // 1) prefer a known name whose extension already matches the real type
  if (ext) {
    const m = names.find(n => n.toLowerCase().endsWith('.' + ext));
    if (m) return m;
  }
  // 2) otherwise take meaningful_name / first name and correct its extension
  let name = a.meaningful_name || names[0] || null;
  if (name && ext) {
    const m = name.match(/\.([a-z0-9]{1,6})$/i);
    if (m && EXEC_EXTS.includes(m[1].toLowerCase()) && m[1].toLowerCase() !== ext) {
      name = name.slice(0, m.index) + '.' + ext;          // fix wrong extension
    } else if (!m) {
      name = name + '.' + ext;                             // add missing extension
    }
  }
  return name || (id ? id.slice(0, 12) : '?');
}
function vtIdFor(kind, value) {
  return kind === 'url' ? b64urlUrl(value) : value;
}
// Direct VirusTotal GUI URL for an entity, so the analyst can open it on VT.
function vtGuiUrl(e) {
  const seg = { file: 'file', domain: 'domain', ip: 'ip-address', url: 'url' }[e.kind];
  if (!seg) return null;
  return `https://www.virustotal.com/gui/${seg}/${encodeURIComponent(vtIdFor(e.kind, e.value))}`;
}
async function sha256Hex(buf) {
  const h = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/* ============================ persistence =============================== */
const LS = {
  set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} },
  get: (k, d) => { try { const x = localStorage.getItem(k); return x ? JSON.parse(x) : d; } catch (e) { return d; } },
  del: k => { try { localStorage.removeItem(k); } catch (e) {} },
};
function saveSettings() { LS.set('iochub.settings', state.settings); }
function loadSettings() {
  Object.assign(state.settings, LS.get('iochub.settings', {}));
  // Materialize autopivot config from defaults on first run; keep saved edits.
  if (!state.settings.autopivot) {
    state.settings.autopivot = JSON.parse(JSON.stringify(DEFAULT_AUTOPIVOT));
  } else {
    // backfill any missing type buckets so the UI always has all four
    const ap = state.settings.autopivot;
    if (typeof ap.depth !== 'number') ap.depth = DEFAULT_AUTOPIVOT.depth;
    ap.types = ap.types || {};
    for (const k of Object.keys(DEFAULT_AUTOPIVOT.types)) {
      if (!ap.types[k]) ap.types[k] = JSON.parse(JSON.stringify(DEFAULT_AUTOPIVOT.types[k]));
      if (typeof ap.types[k].sensitivity !== 'number') ap.types[k].sensitivity = 30;
      if (!Array.isArray(ap.types[k].rules)) ap.types[k].rules = [];
    }
  }
}
// Read an entity attribute by its flattened path. Attributes are stored
// flattened (dotted + [i] indices) in e.attributes, so a direct lookup works.
// For rule paths with an array wildcard (e.g. signature_info.x509[*].serial
// number, or a specific index that may differ from the stored one) we match by
// turning every [N] / [*] in the path into a numeric-index matcher and scanning
// the stored keys. Returns the first match, or undefined.
function attrByPath(e, path) {
  const a = e.attributes || {};
  if (path in a) return a[path];
  // Build a regex: escape everything, then turn escaped bracket-index tokens
  // back into \[\d+\]. We escape first, so the literal characters (including
  // spaces) are preserved exactly; only the index tokens become wildcards.
  const esc = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // after escaping, "[0]" -> "\[0\]" and "[*]" -> "\[\*\]"; replace both forms
  const pattern = esc.replace(/\\\[(?:\d+|\\\*)\\\]/g, '\\[\\d+\\]');
  if (pattern === esc) return undefined;     // no index tokens => nothing to wildcard
  let re;
  try { re = new RegExp('^' + pattern + '$'); } catch (err) { return undefined; }
  for (const k of Object.keys(a)) { if (re.test(k)) return a[k]; }
  return undefined;
}

/* ===================== zero-knowledge crypto layer =====================
   The password never leaves the browser. From it we derive (via PBKDF2-
   HMAC-SHA256, matching the backend) two independent values with different
   salt labels:
     * authSecret  — sent to the backend as the login credential (stored only
                     as an Argon2id hash); the server can verify but not invert.
     * encKey      — an AES-GCM key kept ONLY in memory for this session, used
                     to encrypt/decrypt graphs and the VT key. Never sent.
   Because the two derivations use different salts, the server (which only ever
   sees authSecret) cannot derive encKey, so it cannot read user content. */
const KDF_ITERS = 210000;                       // must match backend auth.rs
const te = new TextEncoder(), td = new TextDecoder();

function b64enc(bytes) { let s = ''; const b = new Uint8Array(bytes); for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
function b64dec(str) { const s = atob(str); const b = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i); return b; }

async function pbkdf2Bits(password, saltStr, bits) {
  const mat = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: te.encode(saltStr), iterations: KDF_ITERS, hash: 'SHA-256' }, mat, bits);
}
// Login credential: PBKDF2 over the password, base64 (matches backend exactly).
async function deriveAuthSecret(password, username) {
  return b64enc(await pbkdf2Bits(password, 'iochub-auth-v1:' + username, 256));
}
// Content key: a *separate* derivation imported as an AES-GCM key (never sent).
async function deriveEncKey(password, username) {
  const raw = await pbkdf2Bits(password, 'iochub-enc-v1:' + username, 256);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
// Encrypt a JS value -> ciphertext envelope {v, iv, ct} (all base64-ish).
async function encryptObj(obj, key = state.encKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = te.encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
  return { v: 1, iv: b64enc(iv), ct: b64enc(ct) };
}
// Decrypt an envelope -> JS value (null if empty/unset).
async function decryptObj(env, key = state.encKey) {
  if (!env || env.empty || !env.ct) return null;
  const iv = b64dec(env.iv), ct = b64dec(env.ct);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(td.decode(pt));
}

/* ===================== sample byte store (IndexedDB) ===================
   Uploaded file bytes are cached in IndexedDB keyed by sha256, so they survive
   reloads and don't bloat the JS heap. They are XOR-obfuscated with a fast key
   (not real crypto — the goal is only that raw PE bytes aren't sitting in
   browser storage in a form an endpoint scanner flags, while keeping store/
   fetch fast). When logged in the XOR key is derived from the session key; the
   exact scheme doesn't matter for security, only that it's reversible. A
   per-tab in-memory map is the fallback if IndexedDB is unavailable. */
const SAMPLE_DB = 'iochub-samples', SAMPLE_STORE = 'blobs';
const MAX_SAMPLE_BYTES = 1024 * 1024 * 1024;  // 1 GB hard ceiling; the user owns their RAM/storage
let _sampleDB = null;
state.fileBlobs = state.fileBlobs || {};       // in-memory fallback / metadata cache

function openSampleDB() {
  if (_sampleDB) return Promise.resolve(_sampleDB);
  return new Promise((resolve, reject) => {
    if (!('indexedDB' in window)) return reject(new Error('no indexeddb'));
    const req = indexedDB.open(SAMPLE_DB, 1);
    req.onupgradeneeded = () => { req.result.createObjectStore(SAMPLE_STORE); };
    req.onsuccess = () => { _sampleDB = req.result; resolve(_sampleDB); };
    req.onerror = () => reject(req.error || new Error('indexeddb open failed'));
  });
}
// A fast repeating-key byte derived from the session; stable within a session.
function sampleXorKey() {
  // Derive 64 bytes from user+token (cheap, non-cryptographic). Falls back to a
  // fixed key when logged out so obfuscation still applies.
  const seed = (state.user || 'anon') + '|' + (state.token || 'iochub-local');
  const k = new Uint8Array(64);
  let h = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) { h ^= seed.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
  for (let i = 0; i < 64; i++) { h ^= (h << 13); h ^= (h >>> 17); h ^= (h << 5); h >>>= 0; k[i] = h & 0xff; }
  return k;
}
function xorBytes(bytes, key) {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key[i % key.length];
  return out;
}
async function putSample(sha256, name, arrayBuf) {
  const bytes = new Uint8Array(arrayBuf);
  // metadata always kept in memory so the UI knows a sample exists
  state.fileBlobs[sha256] = { name, size: bytes.length, stored: true };
  try {
    const db = await openSampleDB();
    const obf = xorBytes(bytes, sampleXorKey());
    await new Promise((res, rej) => {
      const tx = db.transaction(SAMPLE_STORE, 'readwrite');
      tx.objectStore(SAMPLE_STORE).put({ name, size: bytes.length, data: obf.buffer }, sha256);
      tx.oncomplete = res; tx.onerror = () => rej(tx.error);
    });
    return true;
  } catch (e) {
    // Fallback: keep bytes in memory as base64 (older behavior).
    state.fileBlobs[sha256] = { name, size: bytes.length, b64: bufToB64(arrayBuf) };
    return true;
  }
}
// Returns { name, b64 } or null. Tries IndexedDB, then the in-memory fallback.
async function loadSample(sha256) {
  const meta = state.fileBlobs[sha256];
  if (meta && meta.b64) return { name: meta.name, b64: meta.b64 };  // in-memory fallback
  try {
    const db = await openSampleDB();
    const rec = await new Promise((res, rej) => {
      const tx = db.transaction(SAMPLE_STORE, 'readonly');
      const r = tx.objectStore(SAMPLE_STORE).get(sha256);
      r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
    });
    if (!rec) return null;
    const clear = xorBytes(new Uint8Array(rec.data), sampleXorKey());
    return { name: rec.name, b64: bufToB64(clear.buffer) };
  } catch (e) { return null; }
}
function hasSample(sha256) {
  const m = state.fileBlobs[sha256];
  return !!(m && (m.stored || m.b64));
}

// Free browser sample cache to make room for a large single-file analysis:
// drop every cached sample EXCEPT `keepSha` from both the in-memory fallback
// map and the IndexedDB store. Returns the number of samples evicted.
async function evictOtherSamples(keepSha) {
  let evicted = 0;
  // in-memory fallback map
  for (const k of Object.keys(state.fileBlobs)) {
    if (k !== keepSha && state.fileBlobs[k] && state.fileBlobs[k].b64) {
      delete state.fileBlobs[k]; evicted++;
    }
  }
  // IndexedDB store
  try {
    const db = await openSampleDB();
    const keys = await new Promise((res, rej) => {
      const tx = db.transaction(SAMPLE_STORE, 'readonly');
      const r = tx.objectStore(SAMPLE_STORE).getAllKeys();
      r.onsuccess = () => res(r.result || []); r.onerror = () => rej(r.error);
    });
    const toDelete = keys.filter(k => k !== keepSha);
    if (toDelete.length) {
      await new Promise((res, rej) => {
        const tx = db.transaction(SAMPLE_STORE, 'readwrite');
        const store = tx.objectStore(SAMPLE_STORE);
        toDelete.forEach(k => { store.delete(k); });
        tx.oncomplete = res; tx.onerror = () => rej(tx.error);
      });
      // reflect eviction in the metadata cache
      toDelete.forEach(k => { if (state.fileBlobs[k]) state.fileBlobs[k].stored = false; });
      evicted += toDelete.length;
    }
  } catch (e) {/* no IndexedDB or already clear */}
  return evicted;
}

// Central accessor used by static analysis + CAPE: returns {name, b64} for an
// entity's bytes. If none are cached and the entity is a file hash, tries to
// download the sample from VirusTotal (needs a privileged key). Returns null
// (after toasting) if nothing can be obtained.
async function getSampleBytes(e) {
  // 1) local cache (IndexedDB or memory)
  const local = await loadSample(e.value);
  if (local) return local;
  // 2) try VirusTotal download for a file hash
  if (e.kind === 'file') {
    if (!state.vtKey) {
      toast('No file bytes cached and no VT key set — upload the file, or add a VT key to fetch it.', true);
      return null;
    }
    try {
      busy(true, 'fetching sample from VirusTotal…');
      const r = await fetch(backendBase() + '/api/vt/download', {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-vt-key': state.vtKey, ...authHeader() },
        body: JSON.stringify({ sha256: e.value }),
      });
      const j = await r.json().catch(() => ({}));
      if (j.error) { toast('VT download: ' + j.error, true); return null; }
      if (j.status && j.status >= 400) { toast(j.detail || ('VT download HTTP ' + j.status), true); return null; }
      if (!j.content_b64) { toast('VT returned no sample bytes.', true); return null; }
      // cache it for next time
      const name = (state.fileBlobs[e.value] && state.fileBlobs[e.value].name) || (e.attributes && e.attributes['_local.filename']) || (e.value + '.bin');
      const buf = b64dec(j.content_b64);
      await putSample(e.value, name, buf.buffer);
      toast(`fetched sample from VirusTotal (${(j.size/1048576).toFixed(1)} MB) — cached`);
      return { name, b64: j.content_b64 };
    } catch (err) { toast('VT download failed: ' + err.message, true); return null; }
    finally { busy(false); }
  }
  return null;
}

function backendBase() {
  const u = (state.settings.backendUrl || '').trim().replace(/\/$/, '');
  return u; // '' => same origin
}
// Download a file entity's bytes to disk — from local cache if present,
// otherwise fetched from VirusTotal (getSampleBytes handles the fallback).
async function downloadEntitySample(e) {
  if (e.kind !== 'file') return;
  const cached = hasSample(e.value);
  const blob = await getSampleBytes(e);   // cache → VT
  if (!blob) return;                       // getSampleBytes already toasted why
  try {
    const bytes = b64dec(blob.b64);
    const out = new Blob([bytes], { type: 'application/octet-stream' });
    const a = el('a', { href: URL.createObjectURL(out), download: blob.name || (e.value + '.bin') });
    document.body.appendChild(a); a.click(); a.remove();
    toast(`downloaded ${blob.name || e.value.slice(0, 16)} (${cached ? 'from local cache' : 'from VirusTotal'})`);
  } catch (err) { toast('download failed: ' + err.message, true); }
}
function authHeader() { return state.token ? { 'Authorization': 'Bearer ' + state.token } : {}; }

// Generic backend JSON call (auth attached). Throws on transport/401 errors.
async function apiCall(path, { method = 'GET', body = null } = {}) {
  const r = await fetch(backendBase() + path, {
    method,
    headers: { 'content-type': 'application/json', ...authHeader() },
    body: body ? JSON.stringify(body) : undefined,
  }).catch(() => { throw new Error('Backend unreachable — check that you are logged in and it is up.'); });
  if (r.status === 401) throw new Error('Backend login required (top bar → connect…), or your session/source IP changed.');
  const j = await r.json().catch(() => ({}));
  if (j.error) throw new Error(j.error);
  return j;
}

/* ============================ VT request layer ==========================
   All VirusTotal traffic goes through the same-origin backend relay. A direct
   browser->VT call is impossible: VT's API v3 sends no CORS headers, so the
   browser blocks it. The relay forwards the request without storing the key
   (the key travels per-request in the X-VT-Key header). A backend login is
   required. */
async function vt(path, { method = 'GET', body = null } = {}) {
  if (!state.vtKey) throw new Error('No VirusTotal API key set (top bar → settings).');
  if (!state.token) throw new Error('Log in to the backend first (top bar → connect…). VirusTotal calls are relayed through it.');
  state.calls++; $('#stCalls').textContent = state.calls;

  const r = await fetch(backendBase() + '/api/vt/relay', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-vt-key': state.vtKey, ...authHeader() },
    body: JSON.stringify({ path, method, body }),
  }).catch(() => { throw new Error('Relay unreachable — check that you are logged in and the backend is up.'); });
  if (r.status === 401) throw new Error('Relay needs a backend login (top bar → connect…), or your session/source IP changed.');
  const j = await r.json().catch(() => ({}));
  if (j.error) throw new Error('Relay: ' + j.error);
  // relay wraps as {status, body}
  if (j.status && j.status >= 400) throw new Error(`VT ${j.status}: ${vtErr(j.body)}`);
  return j.body;
}
function vtErr(j) {
  return (j && j.error && (j.error.message || j.error.code)) || (j && j.raw) || 'request failed';
}

const vtGetObject = (kind, value) =>
  vt(`/api/v3/${KIND[kind].vt}/${encodeURIComponent(vtIdFor(kind, value))}`);
const vtGetRelationship = (kind, value, rel, limit = 40, cursor = null) =>
  vt(`/api/v3/${KIND[kind].vt}/${encodeURIComponent(vtIdFor(kind, value))}/${rel}?limit=${limit}`
     + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''));
const vtSearch = (query, limit = 40, cursor = null) =>
  vt(`/api/v3/intelligence/search?query=${encodeURIComponent(query)}&limit=${limit}`
     + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''));
// VT v3 paginates via meta.cursor (also exposed as links.next). Pull whichever
// is present so callers can request the next page.
function vtNextCursor(r) {
  if (!r) return null;
  if (r.meta && r.meta.cursor) return r.meta.cursor;
  // links.next is a full URL with a cursor= param; extract it as a fallback
  const next = r.links && r.links.next;
  if (typeof next === 'string') {
    const m = next.match(/[?&]cursor=([^&]+)/);
    if (m) return decodeURIComponent(m[1]);
  }
  return null;
}

// Count helpers for autopivot: ask VT for a minimal page and read the meta
// counters. Relationship endpoints expose meta.count; intelligence search
// exposes meta.total_hits. Both fall back to the returned data length (a lower
// bound) if the counter is absent.
async function vtCountRelationship(kind, value, rel) {
  const r = await vt(`/api/v3/${KIND[kind].vt}/${encodeURIComponent(vtIdFor(kind, value))}/${rel}?limit=1`);
  const c = r && r.meta && (r.meta.count ?? r.meta.total_hits);
  if (typeof c === 'number') return c;
  return Array.isArray(r && r.data) ? r.data.length : 0;
}
async function vtCountSearch(query) {
  const r = await vt(`/api/v3/intelligence/search?query=${encodeURIComponent(query)}&limit=1`);
  const c = r && r.meta && (r.meta.total_hits ?? r.meta.count);
  if (typeof c === 'number') return c;
  return Array.isArray(r && r.data) ? r.data.length : 0;
}

/* ============================ graph model =============================== */
function entityKey(kind, value) { return kind + ':' + value.toLowerCase(); }

function addEntity(kind, value, { silent = false } = {}) {
  value = value.trim();
  if (!value) return null;
  const id = entityKey(kind, value);
  if (!state.G.entities[id]) {
    state.G.entities[id] = {
      id, kind, value,
      // `value` is the canonical indicator: it is what links this entity across
      // enrichments (VT lookups, dedup, edges) and never changes. `name` is a
      // free, user-editable display label that defaults to the indicator.
      name: value,
      label: shortLabel(kind, value),
      attributes: {}, enriched: false, malicious: false,
    };
    cyAddEntity(state.G.entities[id]);
    renderEntityList(); updateStatus();
    if (!silent) toast(`+ ${KIND[kind].label} ${shortLabel(kind, value)}`);
    maybeMispAutoEnrich(state.G.entities[id]);   // background MISP query if configured + toggled
  }
  return state.G.entities[id];
}
// Display name (editable) with a safe fallback to the canonical indicator.
function entName(e) { return (e && e.name && String(e.name).trim()) ? String(e.name) : e.value; }
// Short label for the graph node, derived from the display name.
function entShort(e) {
  const n = entName(e);
  if (e.kind === 'file' && n === e.value) return e.value.slice(0, 12) + '…';
  return n.length > 28 ? n.slice(0, 28) + '…' : n;
}
function shortLabel(kind, v) {
  if (kind === 'file') return v.slice(0, 12) + '…';
  if (kind === 'url') return v.length > 28 ? v.slice(0, 28) + '…' : v;
  return v;
}
function subId(field, value) { return 'sub:' + field + ':' + String(value).toLowerCase().slice(0, 80); }

function addSub(parentEntityId, field, value) {
  const sid = subId(field, value);
  if (!state.G.subs[sid]) {
    state.G.subs[sid] = { id: sid, field, value: String(value), collapsed: false };
    cyAddSub(state.G.subs[sid]);
  }
  addEdge(parentEntityId, sid, field, 'sub');
  updateStatus();
  return sid;
}
function addEdge(source, target, label, kind = 'rel') {
  const id = `e:${source}->${target}:${label}`;
  if (!state.G.edges[id]) {
    state.G.edges[id] = { id, source, target, label, kind };
    cyAddEdge(state.G.edges[id]);
  }
  return id;
}
function removeEntity(id) {
  const e = state.G.entities[id]; if (!e) return;
  delete state.G.entities[id];
  Object.values(state.G.edges).forEach(ed => {
    if (ed.source === id || ed.target === id) delete state.G.edges[ed.id];
  });
  if (state.cy) state.cy.$id(id).remove();
  renderEntityList(); updateStatus();
  if (state.drawerEntity === id) closeDrawer();
}

// Remove a SUB-entity and only its own edges. Any entities that were attached
// to it are intentionally left in place (possibly orphaned) — removing those
// is the user's call.
function removeSub(sid) {
  const s = state.G.subs[sid]; if (!s) return;
  delete state.G.subs[sid];
  Object.values(state.G.edges).forEach(ed => {
    if (ed.source === sid || ed.target === sid) delete state.G.edges[ed.id];
  });
  if (state.cy) state.cy.$id(sid).remove();
  renderEntityList(); updateStatus(); saveDirty();
  if (state.drawerEntity === sid) closeDrawer();
}

/* ============================ cytoscape ================================= */
function buildCyStyle() {
  const accent = cssVar('--accent') || '#c8702a';
  const fg = cssVar('--fg'), fgDim = cssVar('--fg-dim'),
        border = cssVar('--border'), panel2 = cssVar('--panel-2'),
        panel = cssVar('--panel'), gbg = cssVar('--graph-bg'), danger = cssVar('--danger');
  const fontFam = '"DejaVu Sans Mono","JetBrains Mono",monospace';
  return [
    { selector: 'node', style: {
        'font-family': fontFam, 'font-size': 10, 'color': fg,
        'text-outline-color': gbg, 'text-outline-width': 2,
        'text-valign': 'bottom', 'text-margin-y': 3, 'label': 'data(label)',
        // Label size is managed dynamically on zoom (see applyLabelZoom); we
        // disable Cytoscape's auto-hide so labels persist down to the 6px floor.
        'min-zoomed-font-size': 0,
    }},
    { selector: 'node.entity', style: {
        'shape': 'ellipse', 'background-color': panel2,
        'border-color': accent, 'border-width': 1.6,
        'width': 26, 'height': 26,
        'background-opacity': 1,
    }},
    { selector: 'node.entity[label]', style: { 'label': 'data(label)' } },
    // type glyph drawn via text on a child? simpler: prepend glyph into label handled in data
    { selector: 'node.file',   style: { 'background-color': panel2 } },
    { selector: 'node.domain', style: { 'shape': 'round-rectangle' } },
    { selector: 'node.ip',     style: { 'shape': 'rectangle' } },
    { selector: 'node.url',    style: { 'shape': 'diamond', 'width': 30, 'height': 30 } },
    { selector: 'node.mal',    style: { 'border-color': danger, 'border-width': 2.4 } },
    { selector: 'node.cape-running', style: {
        'border-color': accent, 'border-width': 3, 'border-style': 'double',
        'overlay-color': accent, 'overlay-opacity': 0.10, 'overlay-padding': 8 }},
    { selector: 'node.cape-done', style: {
        'border-color': accent, 'border-width': 2.4 }},
    { selector: 'node.sub', style: {
        'shape': 'round-rectangle', 'background-color': panel,
        'border-color': fgDim, 'border-width': 1, 'border-style': 'dashed',
        'width': 'label', 'height': 'label', 'padding': '4px',
        'font-size': 9, 'color': fgDim, 'text-valign': 'center', 'text-margin-y': 0,
        'label': 'data(label)',
    }},
    { selector: 'node.sub.collapsed', style: {
        'label': '', 'width': 8, 'height': 8, 'shape': 'ellipse', 'border-style': 'solid',
        'background-color': accent, 'border-color': accent,
    }},
    { selector: 'node:selected', style: {
        'border-color': accent, 'border-width': 3, 'overlay-color': accent,
        'overlay-opacity': 0.12, 'overlay-padding': 6,
    }},
    // The node(s) whose details are open get a halo. We use the UNDERLAY (not
    // overlay): the underlay is drawn in the node's own shape, so a diamond
    // stays a diamond, a rectangle stays a rectangle, etc. A large padding with
    // low opacity reads as a soft glow that fades at the edges rather than a
    // hard box. (Cytoscape can't apply blur filters to nodes, so generous
    // padding + low opacity is how we get a "dissolving" look on the canvas.)
    // The selected node gets a faint halo around it (its label/string).
    { selector: 'node.focus', style: {
        'underlay-color': accent, 'underlay-opacity': 0.22, 'underlay-padding': 6,
    }},
    // Its directly-connected entities & sub-entities get an even fainter,
    // smaller halo — nothing is hidden or dimmed, the rest stays fully visible.
    { selector: 'node.hl', style: {
        'underlay-color': accent, 'underlay-opacity': 0.10, 'underlay-padding': 3,
    }},
    // An entity with a task running on it (static analysis, host analysis, VT
    // enrich, CAPE submit, MISP query, …) gets a faint halo: the SAME underlay
    // as the focus halo, but the colour is pushed halfway between the accent and
    // the graph background so it reads as a soft "working" glow distinct from
    // selection. (Computed in JS since Cytoscape parses colours itself.)
    { selector: 'node.task-running', style: {
        'underlay-color': mixHex(accent, gbg, 0.5), 'underlay-opacity': 0.22, 'underlay-padding': 6,
    }},
    { selector: 'edge', style: {
        'width': 1, 'line-color': border, 'curve-style': 'bezier',
        'target-arrow-shape': 'none', 'font-family': fontFam, 'font-size': 8,
        'color': fgDim, 'text-rotation': 'autorotate', 'label': 'data(label)',
        'text-background-color': gbg, 'text-background-opacity': 0.85,
        'text-background-padding': 1, 'min-zoomed-font-size': 6,
    }},
    // Edges touching the selected node: the connecting label/string lifts ever
    // so slightly — accent text on a faint accent-tinted background, with the
    // line a touch more present. Matches the node halos; nothing is hidden.
    { selector: 'edge.hl', style: {
        'color': accent, 'font-size': 9,
        'text-background-color': accent, 'text-background-opacity': 0.18,
        'text-background-padding': 2,
        'line-color': accent, 'width': 1.4, 'z-index': 20,
    }},
    { selector: 'edge.sub', style: { 'line-style': 'dotted', 'line-color': fgDim } },
    { selector: 'edge.collapsedrel', style: { 'line-style': 'dashed', 'line-color': accent } },
  ];
}
function cyNodeData(e) {
  return { id: e.id, label: KIND[e.kind].glyph + ' ' + entShort(e), kind: e.kind };
}
function cyAddEntity(e) {
  if (!state.cy) return;
  const pos = nearStart();
  state.cy.add({ group: 'nodes', data: cyNodeData(e), position: pos,
    classes: 'entity ' + e.kind + (e.malicious ? ' mal' : '') });
}
function cyAddSub(s) {
  if (!state.cy) return;
  const node = state.cy.add({ group: 'nodes',
    data: { id: s.id, label: subLabel(s), sub: true },
    position: nearStart(), classes: 'sub' + (s.collapsed ? ' collapsed' : '') });
  if (!state.settings.showSubs) node.style('display', 'none');
}
function subLabel(s) { return `${s.field}=${String(s.value).slice(0, 22)}`; }
function cyAddEdge(ed) {
  if (!state.cy) return;
  if (!state.cy.$id(ed.source).length || !state.cy.$id(ed.target).length) return;
  const node = state.cy.add({ group: 'edges',
    data: { id: ed.id, source: ed.source, target: ed.target, label: ed.label },
    classes: ed.kind === 'sub' ? 'sub' : '' });
  if (ed.kind === 'sub' && !state.settings.showSubs) node.style('display', 'none');
}
function nearStart() {
  const c = state.cy.extent();
  return { x: (c.x1 + c.x2) / 2 + (Math.random() - .5) * 240,
           y: (c.y1 + c.y2) / 2 + (Math.random() - .5) * 240 };
}
// Estimate how much room labels need so the layout can space nodes to keep
// text readable. Returns an ideal edge length and repulsion scaled to the
// longest label currently in the graph.
function layoutSpacing() {
  let maxLen = 6;
  Object.values(state.G.entities).forEach(e => { maxLen = Math.max(maxLen, entShort(e).length); });
  Object.values(state.G.subs).forEach(s => { maxLen = Math.max(maxLen, String(subLabel(s)).length); });
  const n = Object.keys(state.G.entities).length + Object.keys(state.G.subs).length;
  // ~7px per char at the base label size; give edges room for two labels.
  const labelPx = maxLen * 7;
  const ideal = Math.min(420, Math.max(120, labelPx * 2.2));
  // more nodes → push harder so clusters don't collapse onto each other
  const repulsion = Math.min(120000, 26000 + n * 900 + labelPx * 400);
  return { ideal, repulsion, labelPx };
}
// Above this entity count, use the structured (type-banded) layout instead of
// the force-directed cose layout, which tangles on big graphs.
const STRUCTURED_LAYOUT_MIN = 50;

function relayout() {
  if (!state.cy) return;
  const cy = state.cy;
  cy.nodes().unlock();
  const entityCount = Object.keys(state.G.entities || {}).length;
  if (entityCount >= STRUCTURED_LAYOUT_MIN) { structuredLayout(); return; }
  const { ideal, repulsion, labelPx } = layoutSpacing();
  const lay = cy.layout({
    name: 'cose', animate: true, animationDuration: 600, fit: true, padding: 60,
    randomize: true, nodeRepulsion: repulsion, idealEdgeLength: ideal,
    nodeOverlap: Math.max(20, labelPx), componentSpacing: Math.max(120, ideal),
    gravity: 0.25, numIter: 1500, edgeElasticity: 120, nestingFactor: 1.2,
  });
  // After an explicit full reflow, everything is considered "placed" so later
  // incremental adds only move the new nodes.
  lay.one('layoutstop', () => cy.nodes().forEach(n => n.data('_placed', true)));
  lay.run();
}

// Structured layout for large graphs — CLUMP model (from operator feedback):
//   * entities are grouped into CLUMPS of related items. Relatedness is judged
//     primarily by TOPOLOGY (which sub-entities / entities they share), because
//     most relationship-expanded entities have no enrichment attributes yet;
//     shared attributes (ssdeep, registrar, asn…) are used as a tie-breaker.
//   * each entity TYPE owns a broad X-region; its clumps are scattered within
//     that region as tight blobs, NOT columns;
//   * clumps that connect to each other are pulled closer together;
//   * sub-entities live just outside / between the clumps they connect.
const STRUCT_CLUMP_CAP = 14;     // max entities per clump before a new one starts

// Attribute hierarchy used as a TIE-BREAKER for clustering (first present wins).
const CLUMP_KEYS = {
  file:   ['ssdeep', 'signature_info.signers', 'signers', 'imphash', 'pe_info.imphash', 'tlsh', 'vhash', 'type_tag'],
  domain: ['registrar', 'tld'],
  ip:     ['network', 'asn', 'as_owner', 'country', 'continent'],
  url:    ['tld'],
};
function attrClumpKey(e) {
  const a = e.attributes || {};
  for (const k of (CLUMP_KEYS[e.kind] || [])) {
    const v = a[k];
    if (v != null && String(v).trim() !== '') return `${k}=${String(v).slice(0, 60)}`;
  }
  return null;
}

function structuredLayout() {
  const cy = state.cy;
  const G = state.G;
  const KIND_ORDER = { file: 0, domain: 1, ip: 2, url: 3 };
  const kindIdx = k => (KIND_ORDER[k] ?? 4);

  const entIds = Object.keys(G.entities);
  const subIds = Object.keys(G.subs);
  const isSub = id => !!G.subs[id];

  // adjacency (entities + subs)
  const adj = new Map();
  const ensure = id => { if (!adj.has(id)) adj.set(id, []); return adj.get(id); };
  entIds.forEach(ensure); subIds.forEach(ensure);
  Object.values(G.edges).forEach(ed => {
    if (adj.has(ed.source) && adj.has(ed.target)) {
      adj.get(ed.source).push(ed.target);
      adj.get(ed.target).push(ed.source);
    }
  });

  // ---- 1. group entities into clumps by TOPOLOGY ----
  // An entity's clump signature is the set of its connected SUB-ENTITIES (the
  // pivots/relationships that grouped it) plus, if it has none, the set of
  // entities it connects to. Entities sharing that signature clump together.
  // Attribute key is appended so e.g. same-ssdeep files split from same-sub but
  // different-ssdeep ones only when attributes exist.
  function topoKey(id) {
    const e = G.entities[id];
    const nbrs = adj.get(id) || [];
    const subN = nbrs.filter(isSub).sort();
    const attrK = attrClumpKey(e);
    if (subN.length) {
      // group by the set of shared sub-entities (the common case here)
      return `${e.kind}|subs:${subN.join(',')}${attrK ? '|' + attrK : ''}`;
    }
    if (attrK) return `${e.kind}|${attrK}`;
    // no subs, no attrs → group by connected entities (e.g. a file's parents)
    const entN = nbrs.filter(n => !isSub(n)).sort();
    if (entN.length) return `${e.kind}|ents:${entN.slice(0, 4).join(',')}`;
    return null;   // truly isolated
  }

  const buckets = new Map();   // bucketKey -> [entityId,...]
  let singleSeq = 0;
  entIds.forEach(id => {
    let key = topoKey(id);
    if (!key) key = `${G.entities[id].kind}:__iso_${singleSeq++}`;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(id);
  });
  // Split oversized buckets into capped clumps; record each clump's kind + key.
  const clumps = [];   // { id, kind, key, members:[] }
  let clumpSeq = 0;
  for (const [key, members] of buckets) {
    const kind = members.length ? G.entities[members[0]].kind : 'file';
    for (let i = 0; i < members.length; i += STRUCT_CLUMP_CAP) {
      clumps.push({ id: clumpSeq++, kind, key, members: members.slice(i, i + STRUCT_CLUMP_CAP) });
    }
  }
  const clumpOfEntity = {};   // entityId -> clump index
  clumps.forEach((c, ci) => c.members.forEach(id => { clumpOfEntity[id] = ci; }));

  // ---- 2. seed clump centres inside each kind's broad X-region ----
  // Each kind gets a horizontal band; clumps for that kind are scattered across
  // a grid inside the band (so they form blobs, not a column).
  const KIND_REGION_W = 900;        // x-width of one entity-type region
  const REGION_GAP = 240;           // gap between type regions
  const kindsPresent = [...new Set(entIds.map(id => kindIdx(G.entities[id].kind)))].sort((a, b) => a - b);
  const regionX = {};               // kindIdx -> region left edge
  kindsPresent.forEach((k, i) => { regionX[k] = i * (KIND_REGION_W + REGION_GAP); });

  const clumpsByKind = {};
  clumps.forEach((c, ci) => { const k = kindIdx(c.kind); (clumpsByKind[k] = clumpsByKind[k] || []).push(ci); });

  const CC = {};   // clump centre {x,y}
  Object.entries(clumpsByKind).forEach(([k, list]) => {
    const cols = Math.max(1, Math.round(Math.sqrt(list.length)));
    const cellW = KIND_REGION_W / cols;
    const rowsN = Math.ceil(list.length / cols);
    const cellH = Math.max(220, 1600 / Math.max(1, rowsN));
    list.forEach((ci, idx) => {
      const r = Math.floor(idx / cols), c = idx % cols;
      CC[ci] = {
        x: regionX[k] + c * cellW + cellW / 2 + (Math.random() - 0.5) * 40,
        y: r * cellH + cellH / 2 + (Math.random() - 0.5) * 40,
      };
    });
  });

  // ---- 3. pull connected clumps together ----
  // Build clump-to-clump weights from entity edges that cross clumps. Then relax
  // each clump centre toward the weighted average of connected clump centres,
  // but only along Y and only within its kind region on X (keeps type bands).
  const clumpLinks = new Map();   // "a|b" -> weight
  Object.values(G.edges).forEach(ed => {
    const ca = clumpOfEntity[ed.source], cb = clumpOfEntity[ed.target];
    if (ca == null || cb == null || ca === cb) return;
    const key = ca < cb ? `${ca}|${cb}` : `${cb}|${ca}`;
    clumpLinks.set(key, (clumpLinks.get(key) || 0) + 1);
  });
  // also link clumps that share a sub-entity (e.g. same embedded-URL sub)
  subIds.forEach(sid => {
    const nbClumps = [...new Set(adj.get(sid).map(n => clumpOfEntity[n]).filter(c => c != null))];
    for (let i = 0; i < nbClumps.length; i++) for (let j = i + 1; j < nbClumps.length; j++) {
      const a = nbClumps[i], b = nbClumps[j];
      const key = a < b ? `${a}|${b}` : `${b}|${a}`;
      clumpLinks.set(key, (clumpLinks.get(key) || 0) + 1);
    }
  });
  const clumpAdj = new Map();
  clumps.forEach((_, ci) => clumpAdj.set(ci, []));
  for (const [key, w] of clumpLinks) { const [a, b] = key.split('|').map(Number); clumpAdj.get(a).push([b, w]); clumpAdj.get(b).push([a, w]); }

  for (let pass = 0; pass < 8; pass++) {
    const nextY = {};
    clumps.forEach((c, ci) => {
      const links = clumpAdj.get(ci);
      if (!links.length) { nextY[ci] = CC[ci].y; return; }
      let sw = 0, sy = 0, sx = 0;
      for (const [other, w] of links) { sw += w; sy += CC[other].y * w; sx += CC[other].x * w; }
      // pull strongly on Y toward connected clumps; gently nudge X but clamp to region
      nextY[ci] = CC[ci].y * 0.4 + (sy / sw) * 0.6;
      const k = kindIdx(c.kind);
      const targetX = CC[ci].x * 0.75 + (sx / sw) * 0.25;
      const lo = regionX[k] + 40, hi = regionX[k] + KIND_REGION_W - 40;
      CC[ci].x = Math.max(lo, Math.min(hi, targetX));
    });
    clumps.forEach((_, ci) => { CC[ci].y = nextY[ci]; });
  }
  // de-overlap clump centres within each kind so blobs don't sit on each other
  Object.values(clumpsByKind).forEach(list => {
    list.sort((a, b) => CC[a].y - CC[b].y);
    const MINSEP = 200;
    for (let i = 1; i < list.length; i++) {
      if (CC[list[i]].y - CC[list[i - 1]].y < MINSEP) CC[list[i]].y = CC[list[i - 1]].y + MINSEP;
    }
  });

  // ---- 4. place entities inside their clump as a tight blob ----
  const pos = {};
  clumps.forEach((c, ci) => {
    const m = c.members, n = m.length;
    const cols = Math.max(1, Math.ceil(Math.sqrt(n)));
    const SP = 70;   // intra-clump spacing
    m.forEach((id, idx) => {
      const r = Math.floor(idx / cols), col = idx % cols;
      const w = (cols - 1) * SP, h = (Math.ceil(n / cols) - 1) * SP;
      pos[id] = {
        x: CC[ci].x - w / 2 + col * SP + (Math.random() - 0.5) * 12,
        y: CC[ci].y - h / 2 + r * SP + (Math.random() - 0.5) * 12,
      };
    });
  });

  // ---- 5. sub-entities: just outside / between the clumps they connect ----
  // Place each sub at the centroid of its connected entities, nudged outward so
  // it sits in the gap rather than on top of a clump. Disconnected subs go to a
  // band at the bottom.
  let subOrphan = 0;
  const bottomY = Math.max(0, ...Object.values(pos).map(p => p.y)) + 320;
  subIds.forEach(sid => {
    const nbs = adj.get(sid).filter(n => pos[n]);
    if (!nbs.length) {
      pos[sid] = { x: (subOrphan++ % 20) * 150, y: bottomY };
      return;
    }
    let cx = 0, cy2 = 0;
    nbs.forEach(n => { cx += pos[n].x; cy2 += pos[n].y; });
    cx /= nbs.length; cy2 /= nbs.length;
    // nudge toward the global centroid's opposite (push slightly outside the blob)
    pos[sid] = { x: cx + (Math.random() - 0.5) * 90, y: cy2 + 80 + (Math.random() - 0.5) * 60 };
  });

  cy.batch(() => {
    cy.nodes().unlock();
    cy.nodes().forEach(n => { const p = pos[n.id()]; if (p) n.position(p); });
  });
  cy.fit(undefined, 60);
  cy.nodes().forEach(n => n.data('_placed', true));
  toast(`clumped layout · ${clumps.length} clump(s) across ${kindsPresent.length} type region(s)`);
}

function initCy() {
  state.cy = cytoscape({
    container: $('#cy'), style: buildCyStyle(), wheelSensitivity: 0.25,
    minZoom: 0.1, maxZoom: 4,
    boxSelectionEnabled: true,        // drag a box to select many entities
    selectionType: 'additive',        // clicks add to the selection
  });
  // Short left-click opens details; dragging moves the node (we distinguish by
  // movement + duration). Right-click also opens details; right-click on a
  // sub-entity toggles its collapse.
  state.cy.on('tapstart', 'node.entity', evt => {
    const n = evt.target;
    state._tap = { id: n.id(), t: Date.now(), x: n.renderedPosition('x'), y: n.renderedPosition('y'),
      shift: !!(evt.originalEvent && (evt.originalEvent.shiftKey || evt.originalEvent.ctrlKey || evt.originalEvent.metaKey)) };
  });
  state.cy.on('tapend', 'node.entity', evt => {
    const n = evt.target, tp = state._tap; state._tap = null;
    if (!tp || tp.id !== n.id()) return;
    const moved = Math.hypot(n.renderedPosition('x') - tp.x, n.renderedPosition('y') - tp.y);
    const sel = state.cy.$('node.entity:selected');
    // A clean quick click with nothing else selected → open single details.
    if (Date.now() - tp.t < 400 && moved < 6 && !tp.shift && sel.length <= 1) {
      openDrawer(n.id());
    }
    // otherwise Cytoscape's additive selection handles multi-select; the
    // select/unselect handlers below decide whether to show the multi pane.
  });
  state.cy.on('cxttap', 'node.entity', evt => {
    const e = state.G.entities[evt.target.id()]; if (!e) return;
    const oe = evt.originalEvent || {};
    entityContextMenu(e, oe.clientX || 200, oe.clientY || 200);
  });
  state.cy.on('cxttap', 'node.sub', evt => toggleCollapseSub(evt.target.id()));
  // Left-click a sub-entity opens its (append-only) details pane.
  state.cy.on('tap', 'node.sub', evt => { if (!state.selectMode) openSubDrawer(evt.target.id()); });
  $('#cy').addEventListener('contextmenu', e => e.preventDefault());

  // React to selection changes: 2+ selected ENTITIES → multi pane. Sub-entities
  // are never part of a multi-selection, so drop them from any selection.
  const onSelChange = () => {
    state.cy.$('node.sub:selected').unselect();   // subs are ignored in multi-select
    const sel = state.cy.$('node.entity:selected');
    if (sel.length >= 2) { renderMultiDrawer(sel.map(n => n.id())); }
    else if (sel.length <= 1 && state.multiMode) { closeDrawer(); }
    renderEntityList();
  };
  state.cy.on('select unselect', 'node', () => { clearTimeout(state._selT); state._selT = setTimeout(onSelChange, 30); });

  // Keep label text a constant on-screen size when zooming IN, and shrink it
  // only slowly when zooming OUT (down to a ~6px readable floor). See
  // applyLabelZoom; reapply on zoom, on new nodes, and after layout.
  state.cy.on('zoom', scheduleLabelZoom);
  state.cy.on('add', scheduleLabelZoom);
  state.cy.on('layoutstop', applyLabelZoom);
  applyLabelZoom();
}

// "Fishing net" box-select mode. Normal mode: left-drag pans the canvas. Select
// mode: left-drag draws a rectangle and everything inside it joins the
// selection on mouse-up (Cytoscape's native box-select), so panning is disabled
// and the cursor becomes a crosshair. Toggling is purely a left-drag behavior
// switch; scroll-zoom and node dragging still work in both modes.
function toggleSelectMode() {
  if (!state.cy) return;
  state.selectMode = !state.selectMode;
  const cyEl = $('#cy'), btn = $('#btnSelectMode');
  if (state.selectMode) {
    state.cy.userPanningEnabled(false);   // left-drag now draws a select box, not a pan
    state.cy.boxSelectionEnabled(true);
    cyEl.classList.add('selmode');
    if (btn) { btn.classList.add('active'); btn.textContent = '⬚ selecting'; }
    toast('box-select on — drag a rectangle over entities; release to select. Click the button again for normal pan.');
  } else {
    state.cy.userPanningEnabled(true);    // back to drag-to-pan
    state.cy.boxSelectionEnabled(true);   // (box-select on empty canvas still allowed)
    cyEl.classList.remove('selmode');
    if (btn) { btn.classList.remove('active'); btn.textContent = '⬚ select'; }
  }
}

// Cytoscape renders a label at  font-size * zoom  screen pixels. To hold the
// on-screen size we set the model font-size to  targetScreenPx / zoom.
//   * zooming in  (zoom >= 1): target is constant -> text stays the same size.
//   * zooming out (zoom < 1):  target = base * zoom^p with p<1, so it shrinks
//     slower than the graph, floored at 6px (smallest still-readable size).
const LBL = { base: 13, min: 6, subBase: 10, subMin: 6, pow: 0.6, cap: 200 };
function labelModelSize(z, base, min) {
  const screen = z >= 1 ? base : Math.max(min, base * Math.pow(z, LBL.pow));
  return Math.min(LBL.cap, screen / z);
}
function applyLabelZoom() {
  if (!state.cy) return;
  const z = state.cy.zoom();
  if (!z || !isFinite(z)) return;
  const ent = labelModelSize(z, LBL.base, LBL.min);
  const sub = labelModelSize(z, LBL.subBase, LBL.subMin);
  state.cy.batch(() => {
    state.cy.nodes('.entity').style('font-size', ent);
    state.cy.nodes('.sub').style('font-size', sub);
  });
}
let _lblRAF = null;
function scheduleLabelZoom() {
  if (_lblRAF) return;
  _lblRAF = requestAnimationFrame(() => { _lblRAF = null; applyLabelZoom(); });
}
function toggleCollapseSub(id) {
  const s = state.G.subs[id]; if (!s) return;
  s.collapsed = !s.collapsed;
  state.cy.$id(id).toggleClass('collapsed', s.collapsed);
  toast(s.collapsed ? 'sub-entity collapsed' : 'sub-entity expanded');
}

/* ============================ details drawer ============================ */
// Highlight the node(s) the side panel refers to. The selected node gets a
// faint halo; its directly-connected entities and sub-entities get a fainter,
// smaller halo. Nothing is hidden or dimmed — the rest of the graph stays fully
// visible. Applies whenever something is selected (it's lightweight).
function setFocusNodes(ids) {
  if (!state.cy) return;
  const cy = state.cy;
  cy.batch(() => {
    cy.nodes('.focus').removeClass('focus');
    cy.elements('.hl').removeClass('hl');
    if (!ids || !ids.length) return;
    let focus = cy.collection();
    ids.forEach(id => { focus = focus.union(cy.$id(id)); });
    focus.addClass('focus');
    // one-hop neighbours (entities + sub-entities) get the fainter halo
    focus.openNeighborhood('node').not(focus).addClass('hl');
    // the edges joining the selection to its neighbours get their label lifted
    focus.connectedEdges().addClass('hl');
  });
}
// Clear all focus/neighbour halos (used when nothing is focused).
function clearNeighborHighlight() {
  if (state.cy) state.cy.elements('.focus, .hl').removeClass('focus hl');
}
function openDrawer(entId) {
  const e = state.G.entities[entId]; if (!e) return;
  state.multiMode = false;
  state.drawerEntity = entId;
  selectEntity(entId, false);   // don't recenter/zoom the graph just for opening details
  setFocusNodes([entId]);       // make it obvious which node this is
  $('#drawer').classList.add('open');
  renderDrawerHead(e);
  renderDrawerActions(e);
  renderDrawerBody(e);
}
// Close the details/multi pane. Clears selection + multi-mode first so the
// selection-change handler doesn't immediately re-open it.
function closeDrawer() {
  state.multiMode = false; state.multiIds = null; state.drawerEntity = null;
  state.subDrawer = null;
  setFocusNodes([]);
  if (state.cy) state.cy.$('node:selected').unselect();
  $('#drawer').classList.remove('open');
}

/* ----------------------------- sub-entity pane -------------------------
   Sub-entities have no VT object of their own, but they can hold attributes
   collected from the entities they connect, and any of those attributes can
   drive a VT pivot. Storage is APPEND-ONLY: adding never overwrites, values
   accumulate (a sub can legitimately hold many thumbprints, names, etc.), and
   only sub-entities get a per-attribute remove button. */
function entitiesConnectedToSub(sid) {
  const ids = new Set();
  Object.values(state.G.edges).forEach(ed => {
    if (ed.source === sid && state.G.entities[ed.target]) ids.add(ed.target);
    if (ed.target === sid && state.G.entities[ed.source]) ids.add(ed.source);
  });
  return [...ids].map(id => state.G.entities[id]).filter(Boolean);
}
function openSubDrawer(sid) {
  const s = state.G.subs[sid]; if (!s) return;
  s.attrs = s.attrs || [];                 // append-only list of {k, v}
  s.name = s.name || '';
  state.multiMode = false; state.drawerEntity = null; state.subDrawer = sid;
  setFocusNodes([sid]);
  $('#drawer').classList.add('open');

  // head: editable name (defaults to the sub's field=value label)
  const head = $('#drawerHead'); head.innerHTML = '';
  const nameEl = el('div', { class: 'ind', title: 'double-click to rename' }, s.name || subLabel(s));
  nameEl.addEventListener('dblclick', () => startRenameSub(s, nameEl));
  head.append(el('div', { class: 'kind' }, 'sub-entity'), nameEl,
    el('div', { class: 'ind-canon' }, `${esc(s.field)} = ${esc(String(s.value))}`));

  // actions
  const wrap = $('#drawerActions'); wrap.innerHTML = '';
  // If this sub came from a VT pivot, it remembers the query and can re-run it
  // directly — handy after enriching, or to pull newly-seen hits.
  if (s.pivotQuery) {
    wrap.append(el('button', { class: 'primary', onclick: () => reRunSubPivot(s),
      title: 'Re-run the VT Intelligence pivot this sub-entity came from:\n' + s.pivotQuery }, 're-run pivot'));
  }
  wrap.append(
    el('button', { onclick: () => subPullFromConnected(s), title:
      'Collect attributes from the entities connected to this sub-entity (append-only)' }, 'pull from connected'),
    el('button', { onclick: () => subAddAttrPrompt(s), title: 'Add an attribute manually' }, 'add attribute'),
    el('button', { class: s.pivotQuery ? '' : 'primary', onclick: () => pivotSearchSub(s), title:
      'Run a VT Intelligence pivot from the checked attributes (premium key)' }, 'pivot: VT search (checked)'),
    el('button', { onclick: () => startRenameSub(s, nameEl) }, 'rename'),
    el('button', { class: 'danger', onclick: () => { if (confirm('Remove this sub-entity? (connected entities stay in the graph)')) { removeSub(sid); } } }, 'remove'));

  // If this sub remembers a pivot query, show it (read-only) beneath the actions.
  if (s.pivotQuery) {
    wrap.append(el('div', { class: 'hint', style: 'flex-basis:100%;margin-top:4px',
      title: 'the VT query this sub-entity was created from' }, `pivot query: ${s.pivotQuery}`));
  }

  // body: append-only attribute table with per-row remove + pivot checkbox
  const body = $('#drawerBody'); body.innerHTML = '';
  const tools = el('div', { class: 'table-tools' },
    el('span', { class: 'hint' }, `${s.attrs.length} attribute(s) — append-only; values accumulate`));
  body.append(tools);
  if (!s.attrs.length) {
    body.append(el('div', { class: 'hint', style: 'padding:10px' },
      'No attributes yet. Use “pull from connected” to gather values from linked entities, or “add attribute”.'));
  } else {
    const tbl = el('table', { class: 'attrs' });
    tbl.append(el('tr', { class: 'hdr' }, [el('th', { class: 'cb' }, ''), el('th', { class: 'k' }, 'attribute'), el('th', { class: 'v' }, 'value'), el('th', {}, '')]));
    s.attrs.forEach((pair, i) => {
      const cb = el('input', { type: 'checkbox' }); cb.dataset.k = pair.k; cb.dataset.v = pair.v;
      const rm = el('button', { title: 'remove this attribute', onclick: () => { s.attrs.splice(i, 1); saveDirty(); openSubDrawer(sid); } }, '−');
      tbl.append(el('tr', { class: 'ag-row is-entity' }, [
        el('td', { class: 'cb' }, cb),
        el('td', { class: 'k' }, pair.k),
        el('td', { class: 'v mono' }, String(pair.v)),
        el('td', {}, rm) ]));
    });
    body.append(tbl);
  }
  renderEntityList();
}
function startRenameSub(s, holder) {
  const inp = el('input', { class: 'rename-input', type: 'text', value: s.name || '' });
  holder.replaceWith(inp); inp.focus(); inp.select();
  const commit = () => { s.name = inp.value.trim(); if (state.cy) state.cy.$id(s.id).data('label', s.name || subLabel(s)); saveDirty(); openSubDrawer(s.id); };
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') commit(); if (e.key === 'Escape') openSubDrawer(s.id); });
  inp.addEventListener('blur', commit);
}
function subAddAttrPrompt(s) {
  const k = prompt('Attribute name (e.g. thumbprint_sha256):'); if (!k) return;
  const v = prompt(`Value for ${k}:`); if (v == null) return;
  s.attrs.push({ k: k.trim(), v: String(v) });   // append, never overwrite
  saveDirty(); openSubDrawer(s.id);
}
// Pull attributes from connected entities into the sub. Opens a chooser with
// two sections — attributes COMMON to all connected entities, and the rest —
// each attribute being a collapsible group listing the distinct values found
// across the connections (with how many entities had each). The analyst ticks
// the (attribute,value) pairs to copy in. Storage stays append-only and exact
// (key,value) duplicates already on the sub are pre-checked-out.
function subPullFromConnected(s) {
  const ents = entitiesConnectedToSub(s.id);
  if (!ents.length) { toast('no entities connected to this sub-entity', true); return; }

  // Gather: per attribute key -> Map(value -> count of entities with that value)
  const byKey = new Map();
  const keyEntityCount = new Map();   // how many entities have the key at all
  ents.forEach(e => {
    const a = e.attributes || {};
    const seenKeysThisEntity = new Set();
    Object.keys(a).forEach(k => {
      if (k.startsWith('_')) return;
      const v = a[k]; if (v == null || typeof v === 'object') return;
      const val = String(v);
      if (!byKey.has(k)) byKey.set(k, new Map());
      const vm = byKey.get(k);
      vm.set(val, (vm.get(val) || 0) + 1);
      if (!seenKeysThisEntity.has(k)) { seenKeysThisEntity.add(k); keyEntityCount.set(k, (keyEntityCount.get(k) || 0) + 1); }
    });
  });
  if (!byKey.size) { toast('connected entities have no attributes yet — enrich them first', true); return; }

  const total = ents.length;
  const already = new Set((s.attrs || []).map(p => p.k + '\u0000' + p.v));
  const allKeys = [...byKey.keys()].sort();
  const commonKeys = allKeys.filter(k => (keyEntityCount.get(k) || 0) === total);
  const otherKeys = allKeys.filter(k => (keyEntityCount.get(k) || 0) < total);

  const body = el('div');
  body.append(el('div', { class: 'hint', style: 'margin-bottom:8px' },
    `Pulling from ${total} connected entit${total === 1 ? 'y' : 'ies'}. Tick the attribute values to copy onto this sub-entity (append-only). Common = present on all ${total}.`));

  // Renders one collapsible attribute group: header (key + how many entities)
  // and a row per distinct value with a checkbox.
  function attrGroup(k, startOpen) {
    const vm = byKey.get(k);
    const values = [...vm.entries()].sort((a, b) => b[1] - a[1]);   // most-common value first
    const wrapG = el('div', { class: 'ap-rule' });   // reuse the card styling
    const tri = el('span', { class: 'tri' }, startOpen ? '▾' : '▸');
    const head = el('div', { class: 'ag-head', style: 'cursor:pointer; display:flex; gap:6px; align-items:center; padding:2px 0' }, [
      tri, el('b', {}, k), el('span', { class: 'cnt hint' }, `(${values.length} value${values.length === 1 ? '' : 's'} · on ${keyEntityCount.get(k)}/${total})`)]);
    const rows = el('div', {}, []);
    rows.style.display = startOpen ? '' : 'none';
    values.forEach(([val, cnt]) => {
      const dup = already.has(k + '\u0000' + val);
      const cb = el('input', { type: 'checkbox' });
      cb.dataset.k = k; cb.dataset.v = val; cb.disabled = dup;
      const row = el('label', { class: 'qterm', style: 'display:flex; gap:8px; align-items:center' }, [
        cb,
        el('span', { class: 'mono', style: 'flex:1; word-break:break-all' }, val.length > 160 ? val.slice(0, 160) + '…' : val),
        el('span', { class: 'hint' }, dup ? 'already added' : `${cnt}/${total}`)]);
      rows.append(row);
    });
    head.addEventListener('click', () => { const open = rows.style.display === 'none'; rows.style.display = open ? '' : 'none'; tri.textContent = open ? '▾' : '▸'; });
    wrapG.append(head, rows);
    return wrapG;
  }

  const mkSection = (title, keys, openByDefault) => {
    body.append(el('div', { class: 'section-label', style: 'margin:8px 0 4px' }, `${title} (${keys.length})`));
    if (!keys.length) { body.append(el('div', { class: 'hint' }, '—')); return; }
    keys.forEach(k => body.append(attrGroup(k, openByDefault && keys.length <= 8)));
  };
  // Common attributes open by default (usually the interesting shared values);
  // the long tail starts collapsed.
  mkSection('common to all connections', commonKeys, true);
  mkSection('other attributes', otherKeys, false);

  openModal('pull attributes from connections', body, [
    { label: 'add checked', primary: true, onClick: () => {
        let added = 0;
        $$('#modalBody input[type=checkbox]:checked').forEach(cb => {
          const k = cb.dataset.k, v = cb.dataset.v, sig = k + '\u0000' + v;
          if (cb.disabled || already.has(sig)) return;
          already.add(sig); s.attrs.push({ k, v }); added++;
        });
        closeModal();
        saveDirty();
        toast(added ? `added ${added} attribute(s) to the sub-entity` : 'nothing new selected');
        openSubDrawer(s.id);
      } },
    { label: 'select all common', onClick: () => {
        // Tick every still-enabled value under the common-attributes section.
        $$('#modalBody input[type=checkbox]').forEach(cb => { if (!cb.disabled && commonKeys.includes(cb.dataset.k)) cb.checked = true; });
      } },
    { label: 'cancel', onClick: () => closeModal() },
  ]);
}
// Pivot from a sub-entity's checked attributes. A sub has no kind of its own,
// so we borrow the kind of a connected entity (they share context); fall back
// to a free-text query if there's no connected entity.
// Re-run the VT pivot a sub-entity was created from. New hits attach to this
// SAME sub (addSub dedupes on field+value), so the existing pivot cluster grows
// rather than spawning a duplicate. Runs the remembered query verbatim.
async function reRunSubPivot(s) {
  if (!s || !s.pivotQuery) { toast('this sub-entity has no remembered pivot query', true); return; }
  if (!state.token) { toast('Log in to the backend first (top bar → connect…).', true); return; }
  if (!state.vtKey) { toast('Set a VirusTotal key first (settings).', true); return; }
  const q = s.pivotQuery;
  const kind = s.pivotKind || 'file';
  // anchor the re-run on an entity connected to this sub (so the pivot sub is
  // re-created/reused with the same field+value and edges line up)
  const conn = entitiesConnectedToSub(s.id);
  const srcNode = conn.length ? conn[0] : null;
  if (!srcNode) { toast('this sub-entity is not connected to any entity — re-run needs an anchor', true); return; }
  const tk = startTask('vt-pivot (re-run)', s.name || subLabel(s), s.id);
  try {
    busy(true, 'VT pivot (re-run)…');
    const data = await vtSearch(q);
    const items = (data && data.data) || [];
    if (!items.length) { tk.done('no hits'); toast('no hits for the remembered pivot query'); return; }
    const total = data && data.meta && (data.meta.total_hits ?? data.meta.count);
    tk.done(`${items.length}${typeof total === 'number' ? '/' + total : ''} hit(s)`);
    busy(false);
    showHits(srcNode, 'vt-search', items, q,
      { field: s.field, value: s.value, attrLabel: 'pivot', pivotQuery: q, pivotKind: kind }, {
        total: typeof total === 'number' ? total : null,
        cursor: vtNextCursor(data),
        fetchMore: async (cur) => {
          const d = await vtSearch(q, 40, cur);
          return { items: (d && d.data) || [], cursor: vtNextCursor(d),
                   total: (d && d.meta && (d.meta.total_hits ?? d.meta.count)) };
        },
      });
  } catch (err) {
    busy(false);
    if (/\b40[13]\b/.test(err.message)) { tk.fail('needs premium key'); toast('VT Intelligence search needs a premium key.', true); }
    else { tk.fail(err.message); toast('pivot re-run failed: ' + err.message, true); }
  }
}
function pivotSearchSub(s) {
  const checks = $$('#drawerBody table.attrs input[type=checkbox]:checked');
  if (!checks.length) { toast('tick one or more attributes first', true); return; }
  const conn = entitiesConnectedToSub(s.id);
  const kind = conn.length ? conn[0].kind : 'file';
  // Build terms the same way as entity pivots, against this kind's facets.
  const facets = VT_FACETS[kind] || {};
  const scope = VT_SCOPE[kind] ? 'entity:' + VT_SCOPE[kind] : '';
  const terms = [];
  checks.forEach(c => {
    const key = c.dataset.k, v = c.dataset.v;
    const seg = key.split('.')[0].replace(/\[\d+\]$/, '');
    let f = facets[seg];
    if (kind === 'file' && seg === 'signature_info') {
      terms.push({ key, value: v, kind: 'mod', term: `signature:${vtQuote(v)}`, enabled: true, note: 'facet signature' }); return;
    }
    if (!f && kind === 'file' && /imphash$/.test(key)) f = { mod: 'imphash', type: 'str' };
    if (f && f.type === 'date') { const d = vtDate(v); if (d) { terms.push({ key, value: v, kind: 'date', mod: f.mod, dateVal: d, op: '+', enabled: true }); return; } }
    if (f) { terms.push({ key, value: v, kind: 'mod', term: `${f.mod}:${vtQuote(v)}`, enabled: true }); return; }
    if (/^[\w.\- ]+$/.test(v)) { terms.push({ key, value: v, kind: 'free', term: vtQuote(v), enabled: true, note: 'free-text' }); return; }
    terms.push({ key, value: v, kind: 'skip', term: null, enabled: false, note: 'skipped' });
  });
  // Reuse the pivot inspector by stashing a synthetic selection on a faux entity.
  pivotSearchWithTerms(s, kind, scope, terms);
}
// Drawer title: editable display name on top, canonical indicator beneath. The
// indicator is the value used for all enrichment; the name is just a label.
function renderDrawerHead(e) {
  const head = $('#drawerHead'); head.innerHTML = '';
  const nameEl = el('div', { class: 'ind', title: 'double-click to rename',
    ondblclick: () => startRename(e, nameEl) }, entName(e));
  head.append(el('div', { class: 'kind' }, KIND[e.kind].label), nameEl);
  if (entName(e) !== e.value) head.append(el('div', { class: 'ind-canon' }, e.value));
}
// Multi-select details pane: shows attributes shared across the selected
// entities and offers mass VT enrichment + mass static analysis.
function renderMultiDrawer(ids) {
  const ents = ids.map(id => state.G.entities[id]).filter(Boolean);
  if (ents.length < 2) return;
  state.multiMode = true; state.multiIds = ids; state.drawerEntity = null;
  setFocusNodes(ids);
  $('#drawer').classList.add('open');

  // head
  const head = $('#drawerHead'); head.innerHTML = '';
  const kinds = [...new Set(ents.map(e => e.kind))];
  head.append(el('div', { class: 'kind' }, `${ents.length} selected`));
  head.append(el('div', { class: 'ind' }, ents.map(e => entName(e)).slice(0, 6).join(', ') + (ents.length > 6 ? ' …' : '')));
  head.append(el('div', { class: 'ind-canon' }, 'types: ' + kinds.join(', ')));

  // actions
  const wrap = $('#drawerActions'); wrap.innerHTML = '';
  wrap.append(el('button', { class: 'primary', onclick: () => massEnrich(ids),
    title: 'Run VirusTotal enrichment on every selected entity' }, `enrich all (VT) · ${ents.length}`));
  const fileEnts = ents.filter(e => e.kind === 'file');
  if (fileEnts.length) {
    const cached = fileEnts.filter(e => hasSample(e.value)).length;
    wrap.append(el('button', { onclick: () => massStatic(fileEnts.map(e => e.id)),
      title: cached === fileEnts.length
        ? 'Run static analysis on the selected files'
        : `Run static analysis on the ${fileEnts.length} selected file(s); ${fileEnts.length - cached} without cached bytes will be fetched from VT (needs a privileged key)` },
      `static all · ${fileEnts.length}`));
  }
  // Host analysis is ALWAYS offered for a multi-selection; it applies to just
  // the domains + IPs in the selection (files/URLs are skipped). The label shows
  // how many it will act on so it's clear it's a subset.
  const hostEnts = ents.filter(e => e.kind === 'domain' || e.kind === 'ip');
  wrap.append(el('button', {
    onclick: () => massHost(hostEnts.map(e => e.id)),
    disabled: hostEnts.length === 0,
    title: hostEnts.length
      ? `Host analysis (dig/whois/cert for domains, nmap for IPs) on the ${hostEnts.length} applicable selected entity(s)`
      : 'No domains or IPs in the current selection' },
    `host analysis · ${hostEnts.length}`));
  wrap.append(el('button', { onclick: () => autoPivot(ids), title: 'Run autopivot starting from the selected entities' }, `autopivot from here · ${ents.length}`));
  // Bulk XQL: enabled when the selection has files/IPs/domains (the kinds with
  // XQL templates). Acts on just those applicable entities.
  const xqlEnts = ents.filter(e => e.kind === 'file' || e.kind === 'ip' || e.kind === 'domain');
  wrap.append(el('button', {
    onclick: () => showBulkXql(xqlEnts.map(e => e.id)),
    disabled: xqlEnts.length === 0,
    title: xqlEnts.length ? `Generate a consolidated XQL query from the ${xqlEnts.length} applicable selected entity(s)` : 'No files, IPs, or domains in the selection' },
    `XQL · ${xqlEnts.length}`));
  wrap.append(el('button', { onclick: () => { state.cy.$('node:selected').unselect(); closeDrawer(); } }, 'clear selection'));

  // common attributes
  const body = $('#drawerBody'); body.innerHTML = '';
  const withAttrs = ents.filter(e => e.attributes && Object.keys(e.attributes).length);
  if (withAttrs.length < ents.length) {
    body.append(el('div', { class: 'hint', style: 'margin-bottom:8px' },
      `${ents.length - withAttrs.length} of ${ents.length} not yet enriched — “enrich all” to populate attributes, then common values appear here.`));
  }
  // keys present on ALL entities that have attributes
  let commonKeys = null;
  withAttrs.forEach(e => {
    const ks = new Set(Object.keys(e.attributes).filter(k => !k.startsWith('_')));
    commonKeys = commonKeys === null ? ks : new Set([...commonKeys].filter(k => ks.has(k)));
  });
  commonKeys = commonKeys ? [...commonKeys] : [];

  const shared = [];   // same value across all
  const differing = []; // present on all but values differ
  commonKeys.forEach(k => {
    const vals = withAttrs.map(e => JSON.stringify(e.attributes[k]));
    if (vals.every(v => v === vals[0])) shared.push(k); else differing.push(k);
  });

  body.append(el('div', { class: 'section-label', style: 'margin:4px 0' }, `shared attributes (${shared.length})`));
  if (!shared.length) body.append(el('div', { class: 'hint' }, withAttrs.length ? 'no identical values across the selection' : '—'));
  else {
    const base = withAttrs[0].attributes;
    // tools row (filter + expand/collapse), mirroring the single-entity drawer
    const tools = el('div', { class: 'table-tools' });
    const filter = el('input', { class: 'filter', type: 'text', placeholder: 'filter shared attributes…' });
    const exp = el('button', {}, 'expand');
    const colb = el('button', {}, 'collapse');
    tools.append(filter, exp, colb, el('span', { class: 'hint' }, `${shared.length} shared`));
    body.append(tools);
    // Same grouped, collapsible table as the single drawer, with select-all.
    const built = buildAttrTable(shared, k => base[k], { renderValue: (k, v) => renderVal(k, v), markEntities: true });
    exp.addEventListener('click', () => built.setAllGroups(true));
    colb.addEventListener('click', () => built.setAllGroups(false));
    built.wireFilter(filter);
    body.append(built.table);
    body.append(el('button', { style: 'margin-top:6px', onclick: () => pivotSearchMulti(ents) },
      'pivot: VT search (checked shared attrs)'));
  }

  if (differing.length) {
    body.append(el('div', { class: 'section-label', style: 'margin:10px 0 4px' }, `present on all, values differ (${differing.length})`));
    const dl = el('div', { class: 'hint' }, differing.sort().join(', '));
    body.append(dl);
  }
  renderEntityList();
}

async function massEnrich(ids) {
  const ents = ids.map(id => state.G.entities[id]).filter(Boolean);
  const tk = startTask('vt-enrich (bulk)', `0/${ents.length}`);
  let ok = 0, fail = 0;
  busy(true, `VT enrich 0/${ents.length}…`);
  for (let i = 0; i < ents.length; i++) {
    busy(true, `VT enrich ${i + 1}/${ents.length}…`);
    tk.update(`${i + 1}/${ents.length}`);
    try {
      const data = await vtGetObject(ents[i].kind, ents[i].value);
      const attrs = (data && data.data && data.data.attributes) || {};
      mergeAttributes(ents[i], flatten(attrs), 'virustotal');
      ents[i].enriched = true;
      const mal = (attrs.last_analysis_stats && attrs.last_analysis_stats.malicious) || 0;
      ents[i].malicious = mal > 0;
      if (state.cy) state.cy.$id(ents[i].id).toggleClass('mal', ents[i].malicious);
      ok++;
    } catch (e) { fail++; }
  }
  busy(false);
  const summary = `${ok}/${ents.length} enriched${fail ? ` · ${fail} failed` : ''}`;
  fail && !ok ? tk.fail(summary) : tk.done(summary);
  toast(`enriched ${ok}/${ents.length}${fail ? ` (${fail} failed)` : ''}`);
  if (state.multiMode) renderMultiDrawer(ids);
}

// Cap on how much sample data bulk static analysis will hold/transfer at once.
// Files are processed strictly one at a time and each blob is released before
// the next, so peak memory ≈ one file's base64 — but we also refuse to start a
// file that alone exceeds the budget, and we never pre-load all samples.
const BULK_STATIC_BUDGET = 300 * 1024 * 1024; // 300 MB
async function massStatic(ids) {
  const ents = ids.map(id => state.G.entities[id]).filter(Boolean).filter(e => e.kind === 'file');
  if (!ents.length) { toast('no file entities selected', true); return; }
  const tk = startTask('static-analysis (bulk)', `0/${ents.length}`);
  let ok = 0, fail = 0, fetched = 0, skippedBig = 0, processedBytes = 0;
  busy(true, `static 0/${ents.length}…`);
  for (let i = 0; i < ents.length; i++) {
    busy(true, `static ${i + 1}/${ents.length}…`);
    tk.update(`${i + 1}/${ents.length}`);
    // Size gate from metadata if we have it (avoid even loading a giant file).
    const knownSize = (ents[i].attributes && (ents[i].attributes['_local.size'] || ents[i].attributes.size)) || 0;
    if (knownSize && knownSize > BULK_STATIC_BUDGET) { skippedBig++; fail++; continue; }

    // Prefer cached bytes; if absent, fetch from VT (needs a privileged key).
    let blob = await loadSample(ents[i].value);
    if (!blob) { blob = await getSampleBytes(ents[i]); if (blob) fetched++; }
    if (!blob) { fail++; continue; }
    // Estimate decoded size from the base64 length; skip if it alone blows the budget.
    const approxBytes = Math.floor((blob.b64 ? blob.b64.length : 0) * 0.75);
    if (approxBytes > BULK_STATIC_BUDGET) { skippedBig++; fail++; blob = null; continue; }

    try {
      const r = await apiCall('/api/static/analyze', { method: 'POST', body: { filename: blob.name, content_b64: blob.b64 } });
      mergeAttributes(ents[i], flatten((r && r.attributes) || {}), 'static');
      ents[i].enriched = true; ok++; processedBytes += approxBytes;
    } catch (e) { fail++; }
    // Release this file's bytes before moving to the next so memory doesn't grow.
    blob = null;
    // Yield to the event loop / GC between large files.
    await new Promise(res => setTimeout(res, 0));
  }
  busy(false);
  const bits = [`${ok}/${ents.length} analyzed`];
  if (fetched) bits.push(`${fetched} via VT`);
  if (skippedBig) bits.push(`${skippedBig} skipped (> ${BULK_STATIC_BUDGET / 1048576}MB)`);
  if (fail - skippedBig > 0) bits.push(`${fail - skippedBig} failed`);
  const summary = bits.join(' · ');
  fail && !ok ? tk.fail(summary) : tk.done(summary);
  toast('static analysis: ' + summary);
  if (state.multiMode) renderMultiDrawer(ids);
}

// Run host analysis across a selection, applying to ONLY the entities where it
// applies: domains → dig/whois/cert, IPs → nmap. Files/URLs are skipped. One at
// a time so the backend isn't hammered.
async function massHost(ids) {
  const ents = ids.map(id => state.G.entities[id]).filter(Boolean).filter(e => e.kind === 'domain' || e.kind === 'ip');
  if (!ents.length) { toast('no domains or IPs in the selection for host analysis', true); return; }
  if (!state.token) { toast('Log in first (top bar → connect…).', true); return; }
  const tk = startTask('host-analysis (bulk)', `0/${ents.length}`);
  let ok = 0, fail = 0;
  for (let i = 0; i < ents.length; i++) {
    tk.update(`${i + 1}/${ents.length}`);
    busy(true, `host analysis ${i + 1}/${ents.length} — ${shortLabel(ents[i].kind, ents[i].value)}…`);
    try {
      if (ents[i].kind === 'domain') await runHostDomain(ents[i]);
      else await runHostIp(ents[i]);
      ok++;
    } catch (e) { fail++; }
  }
  busy(false);
  const summary = `${ok}/${ents.length} host-analyzed${fail ? ` · ${fail} failed` : ''}`;
  fail && !ok ? tk.fail(summary) : tk.done(summary);
  toast('host analysis: ' + summary);
  if (state.multiMode) renderMultiDrawer(state.multiIds || ids);
}

/* ============================ autopivot ================================
   Expand the whole graph automatically. For every entity, attempt each of its
   VT relationships and each configured attribute rule, but only ADD results
   whose population is at/under that entity type's false-positive sensitivity
   (so ubiquitous infrastructure isn't pulled in). Runs `depth` passes: each
   pass pivots the current frontier, and the entities newly added become the
   next pass's frontier. Dedup MERGES: an added node that already exists is
   reused and the new relationship edge is still drawn to it, so shared
   infrastructure shows up as one node with edges from every source. */

// Map a VT relationship name to the entity kind whose sensitivity governs it
// (i.e. the kind of node it would add). null = not auto-pivotable.
function relAddKind(rel) {
  const t = REL_TARGET[rel];
  if (t === 'resolution') return 'ip';   // resolutions add IPs (and the paired domain)
  if (t === 'file' || t === 'domain' || t === 'ip' || t === 'url') return t;
  return null;
}

// Build a VT Intelligence query for an attribute rule against entity `e`.
// Each part runs its regex (group 1) on the named attribute; all parts must
// match for the rule to fire. Returns the query string or null.
function buildRuleQuery(kind, rule, e) {
  const scope = VT_SCOPE[kind] ? 'entity:' + VT_SCOPE[kind] : '';
  const parts = [];
  for (const p of rule.parts || []) {
    const raw = attrByPath(e, p.attr);
    if (raw == null) return null;
    let captured;
    try {
      const m = String(raw).match(new RegExp(p.regex));
      captured = m ? (m[1] != null ? m[1] : m[0]) : null;
    } catch (err) { return null; }   // bad regex → skip rule
    if (!captured) return null;
    captured = captured.trim();
    // Map the part's facet. Known VT facets pass through; a few need shaping.
    const facet = p.facet || '';
    if (!facet || facet === 'free') { parts.push(vtQuote(captured)); continue; }
    if (facet.includes(':')) {
      // already a fully-qualified facet token prefix like "signature:serial"
      // VT has no serial facet; fall back to the generic signature: modifier.
      const base = facet.split(':')[0];
      parts.push(`${base}:${vtQuote(captured)}`);
      continue;
    }
    // date facets get normalized to YYYY-MM-DD (+ matches that day onward)
    const f = (VT_FACETS[kind] || {})[facet];
    if (f && f.type === 'date') {
      const d = vtDate(captured);
      parts.push(d ? `${facet}:${d}+` : vtQuote(captured));
    } else {
      parts.push(`${facet}:${vtQuote(captured)}`);
    }
  }
  if (!parts.length) return null;
  return [scope, ...parts].filter(Boolean).join(' ');
}

async function autoPivot(startIds) {
  if (!state.token) { toast('Log in to the backend first (top bar → connect…).', true); return; }
  if (!state.vtKey) { toast('Set a VirusTotal key first (settings).', true); return; }
  const ap = state.settings.autopivot || DEFAULT_AUTOPIVOT;
  const depth = Math.max(1, ap.depth || 1);
  const scoped = Array.isArray(startIds) && startIds.length;
  const tk = startTask('autopivot', scoped ? `from ${startIds.length} entity(s) · depth ${depth}` : `depth ${depth}`);
  let added = 0, gated = 0, queries = 0, errors = 0;

  // frontier = entity ids to pivot this pass; start from the given set, or all
  let frontier = scoped ? startIds.filter(id => state.G.entities[id]) : Object.keys(state.G.entities);
  const seenSource = new Set();   // entities already pivoted (don't re-pivot)

  try {
    for (let pass = 0; pass < depth; pass++) {
      if (!frontier.length) break;
      const nextFrontier = new Set();
      for (let fi = 0; fi < frontier.length; fi++) {
        const e = state.G.entities[frontier[fi]];
        if (!e || seenSource.has(e.id)) continue;
        seenSource.add(e.id);
        const typeCfg = (ap.types && ap.types[e.kind]) || { sensitivity: 30, rules: [] };
        const sens = typeCfg.sensitivity ?? 30;
        tk.update(`pass ${pass + 1}/${depth} · ${fi + 1}/${frontier.length} · +${added}`);
        busy(true, `autopivot pass ${pass + 1}/${depth} — ${shortLabel(e.kind, e.value)} (+${added})`);

        // 1) RELATIONSHIPS: gate by count, then fetch + add under threshold
        for (const rel of (RELS[e.kind] || [])) {
          const addKind = relAddKind(rel);
          if (!addKind) continue;                 // non-node relationships skipped
          const relSens = ((ap.types && ap.types[addKind]) || {}).sensitivity ?? sens;
          let count;
          try { count = await vtCountRelationship(e.kind, e.value, rel); queries++; }
          catch (err) { errors++; continue; }
          if (count === 0 || count > relSens) { if (count > relSens) gated++; continue; }
          let items;
          try { const d = await vtGetRelationship(e.kind, e.value, rel, Math.min(40, relSens)); items = (d && d.data) || []; }
          catch (err) { errors++; continue; }
          if (!items.length) continue;
          // one sub-entity per (origin, rel) so each source's path is distinct
          const subId_ = addSub(e.id, rel, `${rel} (${count})`);
          for (const it of items) {
            const res = hitToEntity(rel, it);
            const list = Array.isArray(res) ? res : (res ? [res] : []);
            let prev = subId_;
            list.forEach((m, idx) => {
              const before = !!state.G.entities[entityKey(m.kind, m.value)];
              const ne = addEntity(m.kind, m.value, { silent: true });
              if (!ne) return;
              if (m.label && entName(ne) === ne.value) ne.name = m.label;
              // edge is ALWAYS drawn (dedup merges onto the existing node)
              addEdge(prev, ne.id, idx === 0 ? 'match' : 'resolves');
              prev = ne.id;
              if (!before) { added++; nextFrontier.add(ne.id); }
            });
          }
        }

        // 2) ATTRIBUTE RULES: build query from regex captures, gate, add
        for (const rule of (typeCfg.rules || [])) {
          if (!rule.enabled) continue;
          const q = buildRuleQuery(e.kind, rule, e);
          if (!q) continue;                        // attrs missing / regex no-match
          let count;
          try { count = await vtCountSearch(q); queries++; }
          catch (err) { errors++; continue; }
          if (count === 0 || count > sens) { if (count > sens) gated++; continue; }
          let items;
          try { const d = await vtSearch(q, Math.min(40, sens)); items = (d && d.data) || []; }
          catch (err) { errors++; continue; }
          if (!items.length) continue;
          const subId_ = addSub(e.id, 'autopivot', `${rule.name} (${count})`);
          for (const it of items) {
            const res = hitToEntity('search', it);
            const list = Array.isArray(res) ? res : (res ? [res] : []);
            let prev = subId_;
            list.forEach((m, idx) => {
              const before = !!state.G.entities[entityKey(m.kind, m.value)];
              const ne = addEntity(m.kind, m.value, { silent: true });
              if (!ne) return;
              if (m.label && entName(ne) === ne.value) ne.name = m.label;
              addEdge(prev, ne.id, idx === 0 ? 'match' : 'resolves');
              prev = ne.id;
              if (!before) { added++; nextFrontier.add(ne.id); }
            });
          }
        }
      }
      frontier = [...nextFrontier];
    }
    busy(false);
    relayoutSoft();   // place only the newly-added nodes; keep the rest stable
    tk.done(`+${added} nodes · ${gated} gated · ${queries} queries${errors ? ` · ${errors} errors` : ''}`);
    toast(`autopivot done — added ${added}, gated ${gated} as too common (${queries} VT queries)`);
  } catch (err) {
    busy(false); tk.fail(err.message || 'failed'); toast('autopivot failed: ' + err.message, true);
  }
}

// Pivot from the checked shared attributes of a multi-selection. The shared
// table is a `table.attrs`, so buildTermsFromSelection already reads its checked
// rows. We anchor the pivot on the first selected entity (all share the kind),
// so the resulting sub-entity + hits hang off a real node.
function pivotSearchMulti(ents) {
  const checks = $$('#drawerBody table.attrs input[type=checkbox]:checked').filter(c => c.dataset && c.dataset.k);
  if (!checks.length) { toast('tick one or more shared attributes first', true); return; }
  pivotSearch(ents[0]);
}
function initDrawerResize() {
  const drawer = $('#drawer'), handle = $('#drawerResize');
  if (!handle) return;
  let startX = 0, startW = 0;
  const onMove = ev => {
    const w = Math.max(320, Math.min(window.innerWidth * 0.92, startW + (startX - ev.clientX)));
    drawer.style.setProperty('--drawer-w', w + 'px');
  };
  const onUp = () => {
    drawer.classList.remove('resizing');
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
  };
  handle.addEventListener('mousedown', ev => {
    ev.preventDefault();
    startX = ev.clientX; startW = drawer.getBoundingClientRect().width || 560;
    drawer.classList.add('resizing');
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  });
}

// Single source of truth for an entity's actions, used by BOTH the details
// pane buttons and the right-click context menu so they never drift apart.
// Returns [{ label, title, run, cls?, href? }]. `run` is a click handler.
function entityActions(e) {
  const acts = [];
  acts.push({ label: e.enriched ? 're-enrich (VT)' : 'enrich (VT)', cls: 'primary', title: 'Look this indicator up on VirusTotal and fill its attributes', run: () => runEnrich(e) });
  acts.push({ label: e.mispChecked ? 're-query MISP' : 'MISP', title: 'Query your MISP instance for this indicator (hashes cross-check with VT; tags/comments → misp.*; events & galaxies → sub-entities)', run: () => mispEnrich(e) });
  acts.push({ label: 'pivot: VT search', title: 'VT Intelligence search built from the selected attributes (premium key)', run: () => pivotSearch(e) });
  if (e.kind === 'file') {
    const hasStatic = (e.sources || []).includes('static');
    acts.push({ label: hasStatic ? 're-run static analysis' : 'static analysis', title: 'Analyze the uploaded file locally (hashes, PE, imports, strings, packers)', run: () => runStatic(e) });
    const st = e.cape && e.cape.status;
    if (st === 'running') acts.push({ label: 'CAPE running…', disabled: true, run: () => {} });
    else if (st === 'reported') {
      acts.push({ label: 'view CAPE results', cls: 'primary', title: 'Add the IoCs CAPE found to the graph', run: () => showCapeHits(e, e.cape.indicators || {}) });
      acts.push({ label: 're-detonate', title: 'Run CAPE again', run: () => detonateCape(e) });
    } else acts.push({ label: 'detonate (CAPE)', title: 'Submit/look up this sample in CAPE and pull network IoCs', run: () => detonateCape(e) });
  }
  if (e.kind === 'domain') {
    const hasHost = (e.sources || []).includes('host');
    acts.push({ label: hasHost ? 're-run host analysis' : 'host analysis (dig/whois/cert)', title: 'Live dig + whois + TLS cert from the backend', run: () => runHostDomain(e) });
  }
  if (e.kind === 'ip') {
    const hasHost = (e.sources || []).includes('host');
    acts.push({ label: hasHost ? 're-run port scan' : 'host analysis (nmap port scan)', title: 'Live full TCP port scan + service detection', run: () => runHostIp(e) });
  }
  if (e.kind === 'file' || e.kind === 'ip' || e.kind === 'domain') {
    acts.push({ label: 'XQL', title: 'Generate an XQL query for your XSIAM tenant from this entity', run: () => showXql(e) });
  }
  const vtUrl = vtGuiUrl(e);
  if (vtUrl) acts.push({ label: 'vt ↗', title: 'Open this entity on VirusTotal', href: vtUrl });
  if (e.kind === 'file') acts.push({ label: 'download ⤓', title: 'Download the sample (local cache, or VirusTotal if not cached)', run: () => downloadEntitySample(e) });
  acts.push({ label: 'autopivot from here', title: 'Run autopivot starting from this entity', run: () => autoPivot([e.id]) });
  acts.push({ label: 'remove', cls: 'danger', title: 'Remove entity from the graph', run: () => { if (confirm('Remove entity from graph?')) { removeEntity(e.id); if (state.drawerEntity === e.id) closeDrawer(); } } });
  return acts;
}

function renderDrawerActions(e) {
  const wrap = $('#drawerActions'); wrap.innerHTML = '';
  // "add selected → graph" is details-pane-only (acts on checked attributes there)
  wrap.append(el('button', { onclick: () => addSelectedToGraph(e) }, 'add selected → graph'));
  entityActions(e).forEach(a => {
    if (a.href) { wrap.append(el('a', { class: 'btn-link', href: a.href, target: '_blank', rel: 'noopener noreferrer', title: a.title || '' }, a.label)); return; }
    wrap.append(el('button', { class: a.cls || '', disabled: !!a.disabled, title: a.title || '', onclick: a.run }, a.label));
  });
}

// Right-click context menu for an entity (mirrors the details-pane actions).
let _ctxMenuEl = null;
let _ctxMenuEntityId = null, _ctxMenuLastX = 0, _ctxMenuLastY = 0;
function closeCtxMenu() { if (_ctxMenuEl) { _ctxMenuEl.remove(); _ctxMenuEl = null; _ctxMenuEntityId = null; document.removeEventListener('mousedown', _ctxOutside, true); document.removeEventListener('keydown', _ctxEsc, true); } }
function _ctxOutside(ev) { if (_ctxMenuEl && !_ctxMenuEl.contains(ev.target)) closeCtxMenu(); }
function _ctxEsc(ev) { if (ev.key === 'Escape') closeCtxMenu(); }
function entityContextMenu(e, clientX, clientY) {
  closeCtxMenu();
  _ctxMenuEntityId = e.id; _ctxMenuLastX = clientX; _ctxMenuLastY = clientY;
  const menu = el('div', { class: 'ctx-menu' });
  menu.append(el('div', { class: 'ctx-head' }, shortLabel(e.kind, e.value)));
  entityActions(e).forEach(a => {
    if (a.href) {
      menu.append(el('a', { class: 'ctx-item', href: a.href, target: '_blank', rel: 'noopener noreferrer',
        onclick: () => closeCtxMenu() }, a.label));
      return;
    }
    const item = el('div', { class: 'ctx-item' + (a.cls === 'danger' ? ' danger' : '') + (a.disabled ? ' disabled' : '') }, a.label);
    if (!a.disabled) item.addEventListener('click', () => { closeCtxMenu(); a.run(); });
    menu.append(item);
  });
  // expand-relationship actions (one per VT relationship for this kind). The
  // num/num count sits RIGHTMOST so the little menu keeps its visual cohesion.
  const rels = RELS[e.kind] || [];
  if (rels.length) {
    menu.append(el('div', { class: 'ctx-sep' }));
    rels.forEach(r => {
      const st = (e.relStats && e.relStats[r]) || null;
      const countTxt = st ? `${st.inGraph}/${st.onVt == null ? '?' : st.onVt}` : '';
      const item = el('div', { class: 'ctx-item ctx-expand' }, [
        el('span', { class: 'ctx-exp-label' }, `expand ${r}`),
        el('span', { class: 'ctx-exp-count' }, countTxt),
      ]);
      item.addEventListener('click', () => { closeCtxMenu(); expandRelationship(e, r); });
      menu.append(item);
    });
  }
  document.body.appendChild(menu);
  // position within viewport
  const r = menu.getBoundingClientRect();
  let x = clientX, y = clientY;
  if (x + r.width > window.innerWidth - 8) x = window.innerWidth - r.width - 8;
  if (y + r.height > window.innerHeight - 8) y = window.innerHeight - r.height - 8;
  menu.style.left = Math.max(8, x) + 'px'; menu.style.top = Math.max(8, y) + 'px';
  _ctxMenuEl = menu;
  setTimeout(() => { document.addEventListener('mousedown', _ctxOutside, true); document.addEventListener('keydown', _ctxEsc, true); }, 0);
}

// Right-click context menu for a MULTI-selection (mirrors the multi-details
// pane). Actions apply only to the applicable entities in the selection.
function multiContextMenu(ids, clientX, clientY) {
  const ents = ids.map(id => state.G.entities[id]).filter(Boolean);
  if (!ents.length) return;
  closeCtxMenu();
  const fileEnts = ents.filter(e => e.kind === 'file');
  const hostEnts = ents.filter(e => e.kind === 'domain' || e.kind === 'ip');
  const items = [];
  items.push({ label: `enrich all (VT) · ${ents.length}`, cls: 'primary', run: () => massEnrich(ids) });
  if (fileEnts.length) items.push({ label: `static all · ${fileEnts.length}`, run: () => massStatic(fileEnts.map(e => e.id)) });
  items.push({ label: `host analysis · ${hostEnts.length}`, disabled: hostEnts.length === 0, run: () => massHost(hostEnts.map(e => e.id)) });
  items.push({ label: `autopivot from here · ${ents.length}`, run: () => autoPivot(ids) });
  const xqlEnts = ents.filter(e => e.kind === 'file' || e.kind === 'ip' || e.kind === 'domain');
  items.push({ label: `XQL · ${xqlEnts.length}`, disabled: xqlEnts.length === 0, run: () => showBulkXql(xqlEnts.map(e => e.id)) });
  items.push({ label: 'clear selection', run: () => { state.cy.$('node:selected').unselect(); closeDrawer(); } });

  const menu = el('div', { class: 'ctx-menu' });
  menu.append(el('div', { class: 'ctx-head' }, `${ents.length} selected`));
  items.forEach(a => {
    const item = el('div', { class: 'ctx-item' + (a.cls === 'danger' ? ' danger' : '') + (a.disabled ? ' disabled' : '') }, a.label);
    if (!a.disabled) item.addEventListener('click', () => { closeCtxMenu(); a.run(); });
    menu.append(item);
  });
  document.body.appendChild(menu);
  const r = menu.getBoundingClientRect();
  let x = clientX, y = clientY;
  if (x + r.width > window.innerWidth - 8) x = window.innerWidth - r.width - 8;
  if (y + r.height > window.innerHeight - 8) y = window.innerHeight - r.height - 8;
  menu.style.left = Math.max(8, x) + 'px'; menu.style.top = Math.max(8, y) + 'px';
  _ctxMenuEl = menu;
  setTimeout(() => { document.addEventListener('mousedown', _ctxOutside, true); document.addEventListener('keydown', _ctxEsc, true); }, 0);
}

function renderDrawerBody(e) {
  const body = $('#drawerBody'); body.innerHTML = '';
  const flat = e.attributes;
  const keys = Object.keys(flat);

  // table tools
  const tools = el('div', { class: 'table-tools' });
  const filter = el('input', { class: 'filter', type: 'text', placeholder: 'filter attributes…' });
  const all = el('button', { onclick: () => toggleAll(true) }, 'all');
  const none = el('button', { onclick: () => toggleAll(false) }, 'none');
  const exp = el('button', { onclick: () => setAllGroups(true) }, 'expand');
  const colb = el('button', { onclick: () => setAllGroups(false) }, 'collapse');
  tools.append(filter, all, none, exp, colb,
    el('span', { class: 'hint' }, `${keys.length} attributes` + (e.enriched ? '' : ' — not yet enriched')));
  body.appendChild(tools);

  const built = buildAttrTable(keys, k => flat[k], { renderValue: (k, v) => renderVal(k, v), markEntities: true });
  body.appendChild(built.table);
  state.groupCollapse = built.groupCollapse;
  built.wireFilter(filter);

  // relationships section
  const rels = RELS[e.kind] || [];
  body.appendChild(el('div', { class: 'section-label', style: 'margin:10px' }, 'relationships (expand to pivot)'));
  const rl = el('div', { class: 'rel-list' });
  rels.forEach(r => {
    const target = REL_TARGET[r];
    const st = (e.relStats && e.relStats[r]) || null;
    const countTxt = st ? `${st.inGraph}/${st.onVt == null ? '?' : st.onVt}` : '';
    rl.appendChild(el('div', { class: 'rel', 'data-rel': r }, [
      el('span', { class: 'rn', html: `${esc(r)} <small>→ ${target ? esc(target) : 'info'}</small>` }),
      el('span', { class: 'rel-count', title: 'in graph / on VirusTotal' }, countTxt),
      el('button', { onclick: () => expandRelationship(e, r) }, 'expand'),
    ]));
  });
  body.appendChild(rl);

  function setAllGroups(open) { built.setAllGroups(open); }
  function toggleAll(on) { built.toggleAll(on); }
}

// Build a grouped, collapsible `table.attrs` from a list of attribute keys.
//   keys         : array of dotted/bracketed attribute paths
//   valueFor(k)  : returns the value for key k
//   opts.renderValue(k,v) : optional HTML renderer for the value cell
//   opts.markEntities     : add .is-entity styling for IoC-looking scalars
// Returns { table, groupCollapse, setAllGroups, toggleAll, wireFilter }.
// The header row carries a SELECT-ALL checkbox; per-row checkboxes carry
// data-k / data-v so buildTermsFromSelection() can read the ticked attributes.
function buildAttrTable(keys, valueFor, opts = {}) {
  const groupCollapse = {};
  const tbl = el('table', { class: 'attrs' });
  const grip = el('span', { class: 'col-grip', title: 'drag to resize column' });
  const thK = el('th', { class: 'k' }, [document.createTextNode('attribute'), grip]);
  // header select-all checkbox
  const selAll = el('input', { type: 'checkbox', title: 'select all visible attributes' });
  selAll.addEventListener('change', () => toggleAll(selAll.checked));
  tbl.appendChild(el('tr', { class: 'hdr' },
    [el('th', { class: 'cb' }, selAll), thK, el('th', { class: 'v' }, 'value')]));

  function rowFor(k, v, g) {
    const isEnt = opts.markEntities && looksLikeIoC(v) && !isSubField(k);
    const tr = el('tr', { class: 'ag-row' + (isEnt ? ' is-entity' : '') });
    tr.dataset.k = k.toLowerCase(); tr.dataset.g = g;
    const cb = el('input', { type: 'checkbox' });
    cb.dataset.k = k; cb.dataset.v = String(v);
    cb.addEventListener('change', syncSelAll);
    const valHtml = opts.renderValue ? opts.renderValue(k, v) : esc(String(v));
    tr.append(el('td', { class: 'cb' }, cb), el('td', { class: 'k' }, k), el('td', { class: 'v', html: valHtml }));
    return tr;
  }

  if (!keys.length) {
    tbl.appendChild(el('tr', {}, el('td', { colspan: 3, class: 'hint', style: 'padding:10px' }, 'No attributes.')));
  } else {
    // group by first path segment; bare top-level scalars go to "_general"
    const groups = {};
    keys.forEach(k => {
      const m = k.match(/^([^.[]+)/);
      const head = m ? m[1] : k;
      const g = (k === head) ? '_general' : head;
      (groups[g] = groups[g] || []).push(k);
    });
    const names = Object.keys(groups).sort((a, b) =>
      a === '_general' ? -1 : b === '_general' ? 1 : a.localeCompare(b));
    names.forEach(g => {
      const ks = groups[g].sort();
      const collapsed = g !== '_general' && ks.length > 6;   // big groups start collapsed
      groupCollapse[g] = collapsed;
      const head = el('tr', { class: 'ag-head' });
      head.dataset.g = g;
      head.appendChild(el('td', { class: 'gh', colspan: 3 }, [
        el('span', { class: 'tri' }, collapsed ? '▸' : '▾'),
        document.createTextNode(' ' + (g === '_general' ? 'general' : g) + ' '),
        el('span', { class: 'cnt' }, `(${ks.length})`)]));
      head.addEventListener('click', () => toggleGroup(g));
      tbl.appendChild(head);
      ks.forEach(k => { const tr = rowFor(k, valueFor(k), g); if (collapsed) tr.style.display = 'none'; tbl.appendChild(tr); });
    });
  }

  function setTri(g, c) { const t = $(`tr.ag-head[data-g="${cssEsc(g)}"] .tri`, tbl); if (t) t.textContent = c ? '▸' : '▾'; }
  function applyGroup(g) {
    const c = groupCollapse[g]; setTri(g, c);
    $$(`tr.ag-row[data-g="${cssEsc(g)}"]`, tbl).forEach(tr => tr.style.display = c ? 'none' : '');
  }
  function toggleGroup(g) { groupCollapse[g] = !groupCollapse[g]; applyGroup(g); }
  function setAllGroups(open) { Object.keys(groupCollapse).forEach(g => { groupCollapse[g] = !open; applyGroup(g); }); }
  function toggleAll(on) {
    $$('tr.ag-row', tbl).forEach(tr => { if (tr.style.display !== 'none') { const c = $('input[type=checkbox]', tr); if (c) c.checked = on; } });
    selAll.checked = on; selAll.indeterminate = false;
  }
  // keep the header checkbox state in sync with the row checkboxes
  function syncSelAll() {
    const rows = $$('tr.ag-row', tbl).filter(tr => tr.style.display !== 'none');
    const boxes = rows.map(tr => $('input[type=checkbox]', tr)).filter(Boolean);
    const on = boxes.filter(b => b.checked).length;
    selAll.checked = on > 0 && on === boxes.length;
    selAll.indeterminate = on > 0 && on < boxes.length;
  }
  function wireFilter(filter) {
    if (!filter) return;
    filter.addEventListener('input', () => {
      const q = filter.value.toLowerCase();
      if (!q) { $$('tr.ag-head', tbl).forEach(h => h.style.display = ''); Object.keys(groupCollapse).forEach(applyGroup); syncSelAll(); return; }
      const hit = {};
      $$('tr.ag-row', tbl).forEach(tr => { const show = tr.dataset.k.includes(q); tr.style.display = show ? '' : 'none'; if (show) hit[tr.dataset.g] = true; });
      $$('tr.ag-head', tbl).forEach(h => { h.style.display = hit[h.dataset.g] ? '' : 'none'; setTri(h.dataset.g, false); });
      syncSelAll();
    });
  }

  initColResize(tbl, grip);
  return { table: tbl, groupCollapse, setAllGroups, toggleAll, wireFilter };
}
function initColResize(tbl, grip) {
  let startX = 0, startW = 0;
  const onMove = ev => {
    const w = Math.max(70, Math.min(tbl.clientWidth - 130, startW + (ev.clientX - startX)));
    tbl.style.setProperty('--attr-col', w + 'px');
  };
  const onUp = () => {
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
    document.body.classList.remove('col-resizing');
  };
  grip.addEventListener('mousedown', ev => {
    ev.preventDefault(); ev.stopPropagation();
    startX = ev.clientX;
    startW = parseFloat(getComputedStyle(tbl).getPropertyValue('--attr-col')) || 150;
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    document.body.classList.add('col-resizing');
  });
}
// Date translation layer: if a value is JUST a Unix timestamp (and nothing
// else), render it as an ISO-8601 UTC string. Conservative on purpose — the
// WHOLE value must be a bare integer in a plausible epoch range, so we don't
// turn unrelated numbers (ports, counts, ASNs) into dates.
//   ~10 digits  -> seconds        (≈2001-09 … 2286)
//   ~13 digits  -> milliseconds
//   ~16 digits  -> microseconds   (some APIs use these)
function maybeIsoDate(v) {
  if (v == null) return null;
  const s = String(v).trim();
  if (!/^\d{10}$|^\d{13}$|^\d{16}$/.test(s)) return null;   // bare integer only
  let ms;
  if (s.length === 10) ms = Number(s) * 1000;
  else if (s.length === 13) ms = Number(s);
  else ms = Math.floor(Number(s) / 1000);                    // 16-digit µs → ms
  const d = new Date(ms);
  if (isNaN(d.getTime())) return null;
  // sanity window: 2001-01-01 .. 2100-01-01 so stray 10/13-digit numbers that
  // aren't actually timestamps don't get mislabelled
  const y = d.getUTCFullYear();
  if (y < 2001 || y > 2100) return null;
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');          // YYYY-MM-DDTHH:MM:SSZ
}

function renderVal(k, v) {
  // bare Unix timestamp → ISO date (show the original on hover)
  const iso = maybeIsoDate(v);
  if (iso) return `<span class="isodate" title="${esc(String(v))}">${esc(iso)}</span>`;
  let s = esc(String(v));
  if (/malicious/i.test(k) && Number(v) > 0) s = `<span class="mal">${s}</span>`;
  else if (looksLikeIoC(v)) s = `<span class="badge">${s}</span>`;
  return s;
}
function isSubField(k) {
  const kl = k.toLowerCase();
  return state.settings.subFields.some(f => kl === f.toLowerCase() || kl.startsWith(f.toLowerCase() + '.') || kl.includes(f.toLowerCase()));
}

/* ----- static analysis (backend engine) ----- */
async function runStatic(e) {
  if (!state.token) { toast('Log in first (top bar → connect…).', true); return; }
  if (e.kind !== 'file') { toast('Static analysis applies to file entities.', true); return; }
  const tk = startTask('static-analysis', shortLabel(e.kind, e.value), e.id);
  // This is an explicit, single-file request — no size cap (the user knows
  // their own RAM). For large files, first evict every OTHER cached sample from
  // the browser to free memory/storage for this one ("make way").
  const knownSize = (e.attributes && (e.attributes['_local.size'] || e.attributes.size)) || 0;
  if (knownSize > 300 * 1024 * 1024) {
    const freed = await evictOtherSamples(e.value);
    if (freed) toast(`large file — cleared ${freed} other cached sample(s) to free memory`);
  }
  const blob = await getSampleBytes(e);   // cache → VT download fallback
  if (!blob) { tk.fail('no sample bytes'); return; }
  try {
    busy(true, 'static analysis…');
    const r = await apiCall('/api/static/analyze', { method: 'POST',
      body: { filename: blob.name, content_b64: blob.b64 } });
    const attrs = (r && r.attributes) || {};
    mergeAttributes(e, flatten(attrs), 'static');     // static wins the keys it produces
    e.enriched = true;
    renderDrawerBody(e); renderDrawerActions(e); renderEntityList();
    const n = Object.keys(attrs).length;
    tk.done(`${shortLabel(e.kind, e.value)} · ${n} fields`);
    toast(`static analysis done — ${n} field(s) filled (VT-style)`);
  } catch (err) { tk.fail(err.message); toast('static analysis failed: ' + err.message, true); }
  finally { busy(false); }
}

/* ----- ad-hoc host analysis (live, backend tools) ----- */
async function runHostDomain(e) {
  if (!state.token) { toast('Log in first (top bar → connect…).', true); return; }
  if (e.kind !== 'domain') return;
  const tk = startTask('host-analysis (domain)', shortLabel(e.kind, e.value), e.id);
  try {
    busy(true, 'dig / whois / cert…');
    const r = await apiCall('/api/host/domain', { method: 'POST', body: { domain: e.value } });
    const attrs = (r && r.attributes) || {};
    mergeAttributes(e, flatten(attrs), 'host');
    e.enriched = true;
    // Add resolutions as IPs linked DIRECTLY to this domain with a
    // "resolutions" edge — exactly the way a VT relationship "expand" wires
    // them (addEdge(domain, ip, 'resolutions')). No shared sub-entity, so each
    // domain connects to its own resolved IPs (dedup merges onto existing IPs).
    const res = (r && r.resolutions) || [];
    let addedIps = 0;
    res.forEach(ip => {
      const ne = addEntity('ip', ip, { silent: true });
      if (!ne) return;
      const edgeId = `e:${e.id}->${ne.id}:resolutions`;
      if (!state.G.edges[edgeId]) { addEdge(e.id, ne.id, 'resolutions'); addedIps++; }
    });
    renderDrawerBody(e); renderDrawerActions(e); renderEntityList();
    if (addedIps) relayoutSoft();
    const n = Object.keys(attrs).length;
    tk.done(`${shortLabel(e.kind, e.value)} · ${n} fields · +${addedIps} IPs`);
    toast(`host analysis done — ${n} field(s)${addedIps ? `, +${addedIps} resolution(s)` : ''}`);
  } catch (err) { tk.fail(err.message); toast('host analysis failed: ' + err.message, true); }
  finally { busy(false); }
}

async function runHostIp(e) {
  if (!state.token) { toast('Log in first (top bar → connect…).', true); return; }
  if (e.kind !== 'ip') return;
  const tk = startTask('host-analysis (ip nmap)', shortLabel(e.kind, e.value), e.id);
  try {
    busy(true, 'nmap port scan (can take a while)…');
    const r = await apiCall('/api/host/ip', { method: 'POST', body: { ip: e.value } });
    const attrs = (r && r.attributes) || {};
    mergeAttributes(e, flatten(attrs), 'host');
    e.enriched = true;
    renderDrawerBody(e); renderDrawerActions(e); renderEntityList();
    const openPorts = attrs.open_ports || '';
    tk.done(`${shortLabel(e.kind, e.value)} · ports: ${openPorts || 'none'}`);
    toast(`port scan done — open ports: ${openPorts || 'none found'}`);
  } catch (err) { tk.fail(err.message); toast('port scan failed: ' + err.message, true); }
  finally { busy(false); }
}

/* ----- attribute merge: last run wins per field ----- */
// Overlay freshly-produced flat attributes onto the entity, so re-running an
// engine updates the fields it produces while leaving other fields intact.
// Provenance is tracked per source under e.attributes['_source'] history-free:
// the newest writer simply wins each key.
function mergeAttributes(e, flatAttrs, source) {
  e.attributes = e.attributes || {};
  for (const [k, v] of Object.entries(flatAttrs)) {
    if (k === '_source') continue;
    e.attributes[k] = v;
  }
  // remember which sources have touched this entity (for display only)
  const srcs = new Set((e.sources || []));
  if (source) srcs.add(source);
  e.sources = [...srcs];
}

/* ============================ MISP enrichment ==========================
   MISP supports CORS, so we query the instance DIRECTLY from the browser (no
   backend relay needed). Common attributes (hashes) are merged under the SAME
   keys VirusTotal uses, so they cross-check and can be overwritten by VT.
   MISP-specific data (comments, tags, categories) is stored under misp.* and
   events/galaxies are spawned as sub-entities. */

// MISP attribute types that correspond to our VT attribute keys (so they share
// a column and cross-check). Anything not here is treated as MISP-specific.
const MISP_HASH_MAP = { md5: 'md5', sha1: 'sha1', sha256: 'sha256', sha512: 'sha512',
  ssdeep: 'ssdeep', imphash: 'imphash', tlsh: 'tlsh', vhash: 'vhash', authentihash: 'authentihash',
  'filename|md5': 'md5', 'filename|sha1': 'sha1', 'filename|sha256': 'sha256' };

function mispConfigured() {
  return !!(state.mispKey && (state.settings.mispUrl || '').trim());
}
function mispBase() {
  return (state.settings.mispUrl || '').trim().replace(/\/$/, '');
}

// Query MISP's restSearch for everything matching this entity's value.
async function mispRestSearch(value) {
  const url = mispBase() + '/attributes/restSearch';
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Authorization': state.mispKey, 'Accept': 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ value: String(value), includeContext: true, includeEventTags: true, includeGalaxy: true, limit: 200 }),
  });
  if (!resp.ok) throw new Error(`MISP ${resp.status} ${resp.statusText}`);
  const j = await resp.json();
  // restSearch returns { response: { Attribute: [...] } } (or { response: [...] })
  const r = j && j.response;
  if (Array.isArray(r)) return r;
  return (r && r.Attribute) || [];
}

// Enrich a single entity from MISP. Used by the right-pane button (always) and
// by auto-enrich (when configured + toggled).
async function mispEnrich(e, opts = {}) {
  if (!mispConfigured()) { if (!opts.silent) toast('Set a MISP key and instance URL first (settings).', true); return; }
  const tk = opts.silent ? null : startTask('misp-enrich', shortLabel(e.kind, e.value), e.id);
  try {
    if (!opts.silent) busy(true, 'MISP query…');
    const attrs = await mispRestSearch(e.value);
    if (!attrs.length) { if (tk) tk.done('no MISP hits'); if (!opts.silent) toast('no MISP attributes matched'); e.mispChecked = true; return; }

    const flat = {};                 // VT-compatible + misp.* attributes to merge
    const tags = new Set(), comments = new Set(), categories = new Set();
    const events = new Map();        // eventId -> info
    const galaxies = new Set();      // galaxy cluster names

    const collectTags = (tagArr) => {
      (tagArr || []).forEach(t => {
        const name = t && t.name; if (!name) return;
        // MISP galaxy clusters are encoded as tags like misp-galaxy:malpedia="X"
        if (/^misp-galaxy:|^galaxy:/i.test(name)) galaxies.add(name.replace(/^misp-galaxy:/i, '').replace(/^galaxy:/i, ''));
        else tags.add(name);
      });
    };

    attrs.forEach(a => {
      const t = (a.type || '').toLowerCase();
      // hashes / common types → VT-compatible keys (cross-checkable, VT can overwrite)
      const mapped = MISP_HASH_MAP[t];
      if (mapped && a.value) {
        // composite "filename|hash" → take the hash half
        const v = String(a.value).includes('|') ? String(a.value).split('|').pop() : a.value;
        if (!(mapped in flat)) flat[mapped] = v;   // don't clobber within MISP; VT merge later can overwrite
      }
      if (a.comment) comments.add(a.comment);
      if (a.category) categories.add(a.category);
      collectTags(a.Tag);
      const ev = a.Event;
      if (ev && ev.id) events.set(String(ev.id), ev.info || ('event ' + ev.id));
      // galaxies can also ride on the attribute/event Galaxy field
      (a.Galaxy || (ev && ev.Galaxy) || []).forEach(g => {
        (g.GalaxyCluster || []).forEach(c => { if (c.value) galaxies.add(c.value); });
      });
    });

    // fold collected MISP-specific data into misp.* attributes
    if (tags.size) flat['misp.tags'] = [...tags].join(', ');
    if (comments.size) flat['misp.comments'] = [...comments].join(' | ');
    if (categories.size) flat['misp.categories'] = [...categories].join(', ');
    flat['misp.attribute_count'] = String(attrs.length);
    if (events.size) flat['misp.events'] = [...events.values()].join('; ');

    mergeAttributes(e, flat, 'misp');
    e.mispChecked = true;

    // spawn sub-entities for events and galaxies, linked to this entity
    events.forEach((info, id) => {
      const label = `${info}`.slice(0, 60);
      const sid = subId('event', label);
      if (!state.G.subs[sid]) { state.G.subs[sid] = { id: sid, field: 'event', value: label, collapsed: false, attrs: [{ k: 'misp_event_id', v: id }] }; cyAddSub(state.G.subs[sid]); }
      addEdge(sid, e.id, 'misp event', 'sub');
    });
    galaxies.forEach(g => {
      const label = `${g}`.slice(0, 60);
      const sid = subId('galaxy', label);
      if (!state.G.subs[sid]) { state.G.subs[sid] = { id: sid, field: 'galaxy', value: label, collapsed: false, attrs: [] }; cyAddSub(state.G.subs[sid]); }
      addEdge(sid, e.id, 'misp galaxy', 'sub');
    });

    if (state.drawerEntity === e.id) { renderDrawerBody(e); renderDrawerActions(e); }
    renderEntityList(); saveDirty();
    if (!opts.silent) relayoutSoft();
    const bits = [`${attrs.length} attr`];
    if (events.size) bits.push(`${events.size} event(s)`);
    if (galaxies.size) bits.push(`${galaxies.size} galaxy(s)`);
    if (tk) tk.done(bits.join(' · '));
    if (!opts.silent) toast(`MISP: ${bits.join(' · ')}`);
  } catch (err) {
    if (tk) tk.fail(err.message);
    if (!opts.silent) toast('MISP query failed: ' + err.message, true);
  } finally { if (!opts.silent) busy(false); }
}

// Auto-enrich hook: called after an entity is added. Fires only when MISP is
// configured AND the auto-enrich toggle is on. Runs silently in the background
// and de-dupes so an entity is only auto-queried once.
function maybeMispAutoEnrich(e) {
  if (!state.settings.mispAutoEnrich || !mispConfigured()) return;
  if (!e || e.mispChecked || e._mispAutoQueued) return;
  e._mispAutoQueued = true;
  // fire-and-forget; errors are swallowed in silent mode
  mispEnrich(e, { silent: true }).catch(() => {});
}

/* ----- enrichment (object) ----- */
async function runEnrich(e) {
  const tk = startTask('vt-enrich', shortLabel(e.kind, e.value), e.id);
  try {
    busy(true, 'VT enrich…');
    const data = await vtGetObject(e.kind, e.value);
    const attrs = (data && data.data && data.data.attributes) || {};
    mergeAttributes(e, flatten(attrs), 'virustotal');   // VT wins the keys it returns
    e.enriched = true;
    const mal = (attrs.last_analysis_stats && attrs.last_analysis_stats.malicious) || 0;
    e.malicious = mal > 0;
    if (state.cy) state.cy.$id(e.id).toggleClass('mal', e.malicious);
    renderDrawerBody(e); renderDrawerActions(e); renderEntityList();
    tk.done(`${shortLabel(e.kind, e.value)} · ${Object.keys(e.attributes).length} attrs${mal ? ` · mal ${mal}` : ''}`);
    toast(`enriched ${shortLabel(e.kind, e.value)} — ${Object.keys(e.attributes).length} attrs`);
  } catch (err) { tk.fail(err.message); toast(err.message, true); }
  finally { busy(false); }
}

/* ----- Flow A: add selected attribute rows directly to graph ----- */
function addSelectedToGraph(e) {
  const checks = $$('#drawerBody table.attrs input[type=checkbox]:checked');
  if (!checks.length) { toast('select attribute rows first', true); return; }
  let ents = 0, subs = 0;
  checks.forEach(c => {
    const k = c.dataset.k, v = c.dataset.v;
    const ioc = looksLikeIoC(v);
    if (ioc && !isSubField(k)) {
      const ne = addEntity(ioc, v, { silent: true });
      if (ne) { addEdge(e.id, ne.id, k); ents++; }
    } else {
      addSub(e.id, k.split('.').pop(), v); subs++;
    }
    c.checked = false;
  });
  toast(`added ${ents} entit${ents === 1 ? 'y' : 'ies'}, ${subs} sub-entit${subs === 1 ? 'y' : 'ies'}`);
}

/* ----- Flow B-1: relationship expansion ----- */
// Count how many of a relationship's results are CURRENTLY in the graph.
// Relationship expands link the added entity to this one with an edge LABELLED
// with the relationship name (see showHits: addEdge(src, ne, rel)). So we count
// distinct entity-neighbours reached by an edge whose label is this relationship
// (covers both direct rel edges and any sub-entity carrying the same field).
function relInGraphCount(e, rel) {
  if (!state.cy) return 0;
  const seen = new Set();
  for (const ed of Object.values(state.G.edges)) {
    if (ed.label !== rel) continue;
    let other = null;
    if (ed.source === e.id) other = ed.target;
    else if (ed.target === e.id) other = ed.source;
    if (other && state.G.entities[other]) seen.add(other);
  }
  // also count via a sub-entity of this relationship (attribute-style routing)
  const node = state.cy.$id(e.id);
  if (node.nonempty()) {
    node.neighborhood('node.sub').forEach(s => {
      const sd = state.G.subs[s.id()];
      if (sd && sd.field === rel) {
        s.neighborhood('node.entity').forEach(nbr => { if (nbr.id() !== e.id && state.G.entities[nbr.id()]) seen.add(nbr.id()); });
      }
    });
  }
  return seen.size;
}

// Record/refresh the in-graph vs on-VT counts for a relationship, then redraw
// the relationship rows (details) and any open context menu so the num/num
// stays current.
function setRelStat(e, rel, onVt) {
  e.relStats = e.relStats || {};
  const prev = e.relStats[rel] || {};
  e.relStats[rel] = {
    onVt: (typeof onVt === 'number') ? onVt : (prev.onVt ?? null),
    inGraph: relInGraphCount(e, rel),
  };
}
function refreshRelStat(e, rel, onVt) {
  setRelStat(e, rel, onVt);
  // redraw the details relationship row count if the drawer shows this entity
  if (state.drawerEntity === e.id) {
    const badge = document.querySelector(`#drawerBody .rel[data-rel="${cssEsc(rel)}"] .rel-count`);
    if (badge) { const s = e.relStats[rel]; badge.textContent = `${s.inGraph}/${s.onVt == null ? '?' : s.onVt}`; }
  }
  // if a context menu is open for this entity, refresh it
  if (_ctxMenuEl && _ctxMenuEntityId === e.id) entityContextMenu(e, _ctxMenuLastX, _ctxMenuLastY);
}

async function expandRelationship(e, rel) {
  try {
    busy(true, `VT ${rel}…`);
    // Get the authoritative VT population first, so even an empty/zero result
    // is recorded (→ "0/0"). vtGetRelationship returns meta.count below too.
    const data = await vtGetRelationship(e.kind, e.value, rel);
    const items = (data && data.data) || [];
    const total = data && data.meta && (data.meta.count ?? data.meta.total_hits);
    const onVt = (typeof total === 'number') ? total : items.length;
    refreshRelStat(e, rel, onVt);
    if (!Array.isArray(items) || !items.length) { toast(`no ${rel} on VT (0/0)`); return; }
    const cursor = vtNextCursor(data);
    showHits(e, rel, items, '', null, {
      total: typeof total === 'number' ? total : null,
      cursor,
      fetchMore: async (cur) => {
        const d = await vtGetRelationship(e.kind, e.value, rel, 40, cur);
        return { items: (d && d.data) || [], cursor: vtNextCursor(d),
                 total: (d && d.meta && (d.meta.count ?? d.meta.total_hits)) };
      },
      onAdded: () => refreshRelStat(e, rel, onVt),   // update num/num after adds
    });
  } catch (err) { toast(err.message, true); }
  finally { busy(false); }
}

/* ----- Flow B-2: VT Intelligence search from selected attributes ----- */
// Map a VT object's attribute (by its first path segment) to the real VT
// Intelligence *search facet* for that entity type, so selected attributes
// become proper modifier queries (registrar:"…", creation_date:2020-02-10+, …)
// instead of plain free-text. Sources: VT domain/IP/file/URL search-modifier
// docs. type 'str' => quoted facet match; 'date' => date facet with +/-.
const VT_SCOPE = { file: 'file', domain: 'domain', ip: 'ip', url: 'url' };
const VT_FACETS = {
  domain: {
    registrar: { mod: 'registrar', type: 'str' },
    creation_date: { mod: 'creation_date', type: 'date' },
    last_update_date: { mod: 'last_update_date', type: 'date' },
    last_modification_date: { mod: 'last_modification_date', type: 'date' },
    jarm: { mod: 'jarm', type: 'str' },
    categories: { mod: 'category', type: 'str' },
    tags: { mod: 'tag', type: 'str' },
    tld: { mod: 'tld', type: 'str' },
    whois: { mod: 'whois', type: 'str' },
  },
  ip: {
    as_owner: { mod: 'aso', type: 'str' },
    asn: { mod: 'asn', type: 'str' },
    country: { mod: 'country', type: 'str' },
    continent: { mod: 'continent', type: 'str' },
    jarm: { mod: 'jarm', type: 'str' },
    last_modification_date: { mod: 'last_modification_date', type: 'date' },
    tags: { mod: 'tag', type: 'str' },
    whois: { mod: 'whois', type: 'str' },
  },
  url: {
    tags: { mod: 'tag', type: 'str' },
    categories: { mod: 'category', type: 'str' },
    tld: { mod: 'tld', type: 'str' },
    last_modification_date: { mod: 'last_modification_date', type: 'date' },
  },
  file: {
    type_tag: { mod: 'type', type: 'str' },
    tags: { mod: 'tag', type: 'str' },
    ssdeep: { mod: 'ssdeep', type: 'str' },
    vhash: { mod: 'vhash', type: 'str' },
    tlsh: { mod: 'tlsh', type: 'str' },
    meaningful_name: { mod: 'name', type: 'str' },
    names: { mod: 'name', type: 'str' },
    first_submission_date: { mod: 'fs', type: 'date' },
    last_submission_date: { mod: 'ls', type: 'date' },
    creation_date: { mod: 'generated', type: 'date' },
    // Authenticode signer name / org / cert thumbprint / serial all search well
    // under VT's `signature:` facet, far better than free-text.
    signature_info: { mod: 'signature', type: 'str' },
  },
};

function vtQuote(v) {
  // Quote unless it's a single bare token of safe characters.
  return /^[\w.\-]+$/.test(v) ? v : '"' + String(v).replace(/"/g, '') + '"';
}
// VT date facets take YYYY-MM-DD. Attribute values are usually epoch seconds.
function vtDate(v) {
  if (/^\d{9,11}$/.test(v)) {
    const d = new Date(Number(v) * 1000);
    return isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
  }
  const m = String(v).match(/\d{4}-\d{2}-\d{2}/);
  return m ? m[0] : null;
}
function termText(t) {
  if (!t.enabled) return null;
  if (t.kind === 'date') return `${t.mod}:${t.dateVal}${t.op}`;
  return t.term || null;
}

// Build rich term descriptors from the checked attribute rows for entity `kind`.
function buildTermsFromSelection(kind) {
  const checks = $$('#drawerBody table.attrs input[type=checkbox]:checked');
  const facets = VT_FACETS[kind] || {};
  const scope = VT_SCOPE[kind] ? 'entity:' + VT_SCOPE[kind] : '';
  const terms = [];
  checks.forEach(c => {
    const key = c.dataset.k, v = c.dataset.v;
    const seg = key.split('.')[0].replace(/\[\d+\]$/, '');
    let f = facets[seg];
    if (!f && kind === 'file' && /imphash$/.test(key)) f = { mod: 'imphash', type: 'str' };
    // signature_info.* — signer name / org / thumbprint / serial search well as
    // signature:"value". The validity date subfields are not useful that way,
    // so skip those rather than forcing them into the facet.
    if (kind === 'file' && seg === 'signature_info') {
      if (/valid|date|before|after/i.test(key)) {
        terms.push({ key, value: v, kind: 'skip', term: null, enabled: false, note: 'skipped — signature date not a useful search term' });
        return;
      }
      terms.push({ key, value: v, kind: 'mod', term: `signature:${vtQuote(v)}`, enabled: true, note: 'facet signature' });
      return;
    }
    if (f && f.type === 'date') {
      const d = vtDate(v);
      if (d) { terms.push({ key, value: v, kind: 'date', mod: f.mod, dateVal: d, op: '+', enabled: true, note: `date facet ${f.mod}` }); return; }
      // fall through to free-text if we couldn't parse a date
    }
    if (f) { terms.push({ key, value: v, kind: 'mod', term: `${f.mod}:${vtQuote(v)}`, enabled: true, note: `facet ${f.mod}` }); return; }
    if (/^[\w.\- ]+$/.test(v)) { terms.push({ key, value: v, kind: 'free', term: vtQuote(v), enabled: true, note: 'free-text (no facet for this attribute)' }); return; }
    terms.push({ key, value: v, kind: 'skip', term: null, enabled: false, note: 'skipped — no facet and value unsuitable for free-text' });
  });
  return { scope, terms };
}
function composeQuery(scope, terms) {
  const parts = terms.map(termText).filter(Boolean);
  return [scope, ...parts].filter(Boolean).join(' ');
}

// Show the constructed VT query before running it. Users can toggle which
// attributes contribute, set a before/after operator on date facets, and
// hand-edit the final query — useful for troubleshooting multi-attribute
// searches (e.g. registrar + change date) that behave unexpectedly.
// Tiny helper: in-memory graph is the source of truth; this just refreshes the
// status counters after a mutation (explicit save-to-slot persists the graph).
function saveDirty() { try { updateStatus(); } catch (e) {} }

/* ============================ XQL (XSIAM) ==============================
   Generate an XQL query for an XSIAM tenant from the selected entity. There is
   no live connector yet — this just builds the query and lets the analyst copy
   it. Which filter clauses appear depends on what's checked in the attribute
   table when the button is pressed (and on the file type for files). */
function isExecutableFile(a) {
  a = a || {};
  const tag = String(a.type_tag || '').toLowerCase();
  if (tag === 'peexe' || tag === 'pedll' || tag === 'elf' || tag === 'macho') return true;
  const ext = fileType(a);
  return !!ext && ['exe', 'dll', 'sys', 'scr', 'com', 'elf', 'so'].includes(ext);
}
// Read the attribute paths currently checked in the details table.
function checkedAttrKeys() {
  return $$('#drawerBody table.attrs input[type=checkbox]:checked').map(c => c.dataset.k);
}
function xqlEscape(v) { return String(v).replace(/"/g, '\\"'); }

// Bulk XQL: consolidate a multi-selection of files (or IPs) into ONE query.
// Equality becomes `in (...)`, "contains" becomes a regexp (`~=`) of pipe-joined
// values, and file path/name attributes go through action_process_image_path.
// Optional `keys` (attribute paths) restricts which attribute classes are
// included; when omitted, every populated value of each class is used.
function buildBulkXqlQuery(ents, keys = null) {
  ents = (ents || []).filter(Boolean);
  if (!ents.length) return '';
  const want = (re) => !keys || !keys.length || keys.some(k => re.test(k));
  const uniq = (arr) => [...new Set(arr.filter(v => v != null && String(v).trim() !== ''))];
  const inList = (vals) => uniq(vals).map(v => `"${xqlEscape(v)}"`).join(',');
  // regexp alternation, with regex metachars in each value escaped
  const rxAlt = (vals) => uniq(vals).map(v => xqlRegexEscape(v)).join('|');

  const kind = ents[0].kind;

  if (kind === 'file') {
    const execEnts = ents.filter(e => isExecutableFile(e.attributes || {}));
    const otherEnts = ents.filter(e => !isExecutableFile(e.attributes || {}));
    // If the selection is all-or-mostly executables, build the process-events
    // query; otherwise the generic file-events one. Mixed selections favor the
    // executable form (most IoC hunting targets process execution).
    const useExec = execEnts.length >= otherEnts.length;
    const pool = useExec ? (execEnts.length ? execEnts : ents) : (otherEnts.length ? otherEnts : ents);

    if (useExec) {
      const shas = pool.map(e => (e.attributes && e.attributes.sha256) || e.value);
      const infos = pool.flatMap(e => {
        const a = e.attributes || {};
        const out = [];
        if (a['pe_info.imphash'] || a.imphash) out.push(a['pe_info.imphash'] || a.imphash);
        const fk = Object.keys(a).find(k => /file_?info/i.test(k));
        if (fk && a[fk]) out.push(a[fk]);
        return out;
      });
      const signers = pool.map(e => sigVendorOf(e.attributes || {}));
      // file path / name → path regexp (per the spec)
      const paths = pool.flatMap(e => {
        const a = e.attributes || {};
        const out = [];
        const nm = fileDisplayName(a, e.value);
        if (nm && nm !== e.value) out.push(nm);
        Object.keys(a).filter(k => /(_local\.)?(file)?name$|meaningful_name|image_path|file_path|path$/i.test(k))
          .forEach(k => { if (a[k]) out.push(a[k]); });
        return out;
      });

      const filters = [];
      if (want(/(^|\.)sha256$/i)) { const s = inList(shas); if (s) filters.push(`action_process_image_sha256 in (${s})`); }
      if (want(/imphash|file_?info|pe_info/i)) { const r = rxAlt(infos); if (r) filters.push(`action_process_file_info ~="${r}"`); }
      if (want(/signature_info|signer|vendor/i)) { const s = inList(signers); if (s) filters.push(`action_process_signature_vendor in (${s})`); }
      if (want(/name|meaningful_name|path/i)) { const r = rxAlt(paths); if (r) filters.push(`action_process_image_path ~="${r}"`); }
      const tail = filters.length ? ' | filter ' + filters.join(' and ') : '';
      return 'dataset = xdr_data  | fields event_type, event_sub_type, agent_hostname, '
        + 'actor_effective_username, action_process_image_path, action_process_image_sha256, '
        + 'action_process_signature_vendor, action_process_file_info | filter event_type = 1'
        + tail;
    } else {
      const shas = pool.map(e => (e.attributes && e.attributes.sha256) || e.value);
      const names = pool.map(e => fileDisplayName(e.attributes || {}, e.value));
      const filters = [];
      if (want(/(^|\.)sha256$/i)) { const s = inList(shas); if (s) filters.push(`action_file_sha256 in (${s})`); }
      if (want(/name|meaningful_name|path/i)) { const r = rxAlt(names); if (r) filters.push(`action_file_path ~="${r}"`); }
      const tail = filters.length ? ' | filter ' + filters.join(' and ') : '';
      return 'dataset = xdr_data  | fields event_type, event_sub_type, agent_hostname, '
        + 'actor_effective_username, action_file_sha256, action_file_name, action_file_path, '
        + 'actor_process_image_sha256, actor_process_image_path | filter event_type = ENUM.FILE'
        + tail;
    }
  }

  if (kind === 'ip') {
    const ips = inList(ents.map(e => e.value));
    return 'dataset = zscaler_nssweblog_raw  | fields suser, request, requestClientApplication, '
      + `dst, src, shost  | filter dst in (${ips})`;
  }
  if (kind === 'domain') {
    const rx = rxAlt(ents.map(e => e.value));
    return 'dataset = zscaler_nssweblog_raw  | fields suser, request, requestClientApplication, '
      + `dst, src, shost  | filter request ~="${rx}"`;
  }
  return '';
}
// Escape regex metacharacters in a value used inside an XQL `~=` alternation.
function xqlRegexEscape(v) {
  return String(v).replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/"/g, '\\"');
}

function buildXqlQuery(e) {
  const a = e.attributes || {};
  const checked = checkedAttrKeys();
  const isChecked = pred => checked.some(pred);
  const anyChecked = checked.length > 0;

  if (e.kind === 'file') {
    const sha = a.sha256 || (e.kind === 'file' ? e.value : '');
    if (isExecutableFile(a)) {
      // Decide which clauses to include. If the user checked specific rows we
      // honor exactly those; otherwise include whatever data we actually have.
      const wantSha = anyChecked ? isChecked(k => /(^|\.)sha256$/i.test(k)) : !!sha;
      const fileInfo = a['pe_info.imphash'] || a.imphash ||
        (Object.keys(a).find(k => /file_?info/i.test(k)) ? a[Object.keys(a).find(k => /file_?info/i.test(k))] : '');
      const wantInfo = anyChecked ? isChecked(k => /imphash|file_?info|pe_info/i.test(k)) : !!fileInfo;
      const signer = sigVendorOf(a);
      const wantSigner = anyChecked ? isChecked(k => /signature_info/i.test(k)) : !!signer;

      const filters = [];
      if (wantSha && sha) filters.push(`action_process_image_sha256 = "${xqlEscape(sha)}"`);
      if (wantInfo && fileInfo) filters.push(`action_process_file_info contains "${xqlEscape(fileInfo)}"`);
      if (wantSigner && signer) filters.push(`action_process_signature_vendor = "${xqlEscape(signer)}"`);
      const tail = filters.length ? ' | filter ' + filters.join(' and ') : '';
      return 'dataset = xdr_data  | fields event_type, event_sub_type, agent_hostname, '
        + 'actor_effective_username, action_process_image_path, action_process_image_sha256, '
        + 'action_process_signature_vendor, action_process_file_info | filter event_type = 1'
        + tail;
    } else {
      const name = fileDisplayName(a, e.value);
      const wantSha = anyChecked ? isChecked(k => /(^|\.)sha256$/i.test(k)) : !!sha;
      const wantName = anyChecked ? isChecked(k => /name|meaningful_name/i.test(k)) : !!name;
      const filters = [];
      if (wantSha && sha) filters.push(`action_file_sha256 = "${xqlEscape(sha)}"`);
      if (wantName && name) filters.push(`action_file_name = "${xqlEscape(name)}"`);
      const tail = filters.length ? ' | filter ' + filters.join(' and ') : '';
      return 'dataset = xdr_data  | fields event_type, event_sub_type, agent_hostname, '
        + 'actor_effective_username, action_file_sha256, action_file_name, action_file_path, '
        + 'actor_process_image_sha256, actor_process_image_path, action_file_name | filter event_type = ENUM.FILE'
        + tail;
    }
  }
  if (e.kind === 'ip') {
    return 'dataset = zscaler_nssweblog_raw  | fields suser, request, requestClientApplication, '
      + `dst, src, shost  | filter dst = "${xqlEscape(e.value)}"`;
  }
  if (e.kind === 'domain') {
    return 'dataset = zscaler_nssweblog_raw  | fields suser, request, requestClientApplication, '
      + `dst, src, shost  | filter request contains "${xqlEscape(e.value)}"`;
  }
  return '';
}
// Leaf signer vendor from a (possibly chained) signature_info.signers value.
function sigVendorOf(a) {
  a = a || {};
  const s = a['signature_info.signers'] || a.signers;
  if (typeof s === 'string' && s) return s.split(';')[0].trim();
  // also try x509[*].name forms
  const k = Object.keys(a).find(k => /signature_info.*name$/i.test(k));
  return k ? String(a[k]) : '';
}

// Bulk XQL for a multi-selection: builds one consolidated query across the
// applicable entities (files → process/file events; IPs/domains → zscaler).
// XQL templates differ by kind, so we generate per-kind sections.
function showBulkXql(ids) {
  const ents = (ids || []).map(id => state.G.entities[id]).filter(Boolean);
  const byKind = { file: [], ip: [], domain: [] };
  ents.forEach(e => { if (byKind[e.kind]) byKind[e.kind].push(e); });
  const sections = [];
  ['file', 'ip', 'domain'].forEach(k => { if (byKind[k].length) sections.push({ kind: k, q: buildBulkXqlQuery(byKind[k]) }); });
  if (!sections.length) { toast('select files, IPs, or domains to build an XQL query', true); return; }

  const body = el('div');
  const fileN = byKind.file.length, ipN = byKind.ip.length, domN = byKind.domain.length;
  const counts = [fileN && `${fileN} file(s)`, ipN && `${ipN} IP(s)`, domN && `${domN} domain(s)`].filter(Boolean).join(', ');
  body.appendChild(el('div', { class: 'hint', style: 'margin-bottom:8px' },
    `Bulk XQL for your XSIAM tenant from the selection (${counts}). Equality becomes `
    + '"in (…)" lists, "contains" becomes a regexp (~=) of pipe-joined values, and file '
    + 'names/paths use action_process_image_path. No live connector yet — copy into XSIAM.'
    + (sections.length > 1 ? ' Each entity type produces its own query (different datasets).' : '')));

  sections.forEach(sec => {
    if (sections.length > 1) body.appendChild(el('div', { class: 'section-label', style: 'margin:8px 0 4px' }, sec.kind + ' query'));
    const box = el('textarea', { class: 'qbox mono', rows: 7, spellcheck: 'false' });
    box.value = sec.q; box.dataset.kind = sec.kind;
    body.appendChild(box);
  });

  openModal('XQL · XSIAM (bulk)', body, [
    { label: 'copy all', primary: true, onClick: () => {
        const all = $$('textarea.qbox', body).map(b => b.value).join('\n\n');
        navigator.clipboard && navigator.clipboard.writeText(all); toast('XQL quer' + (sections.length > 1 ? 'ies' : 'y') + ' copied');
      } },
    { label: 'close', onClick: () => closeModal() },
  ]);
}

function showXql(e) {
  const q = buildXqlQuery(e);
  const body = el('div');
  body.appendChild(el('div', { class: 'hint', style: 'margin-bottom:8px' },
    'XQL query for your XSIAM tenant, generated from this entity'
    + (e.kind === 'file' ? ' and any checked attributes (sha256 / file info / signer).' : '.')
    + ' No live connector yet — copy this into XSIAM for now. Tick or untick attributes in the '
    + 'details table to change which filters are included, then reopen XQL.'));
  const box = el('textarea', { class: 'qbox mono', rows: 7, spellcheck: 'false' });
  box.value = q;
  body.appendChild(box);
  openModal('XQL · XSIAM query', body, [
    { label: 'copy query', primary: true, onClick: () => { navigator.clipboard && navigator.clipboard.writeText(box.value); toast('XQL query copied'); } },
    { label: 'close', onClick: () => closeModal() },
  ]);
}

function pivotSearch(e) {
  const { scope, terms } = buildTermsFromSelection(e.kind);
  if (!terms.length) { toast('select one or more attributes to combine into a search', true); return; }
  pivotSearchWithTerms(e, e.kind, scope, terms);
}

// The shared pivot inspector. `srcNode` is the entity OR sub-entity the results
// will hang off (origin → pivot sub → hits). `kind` governs the facets shown.
function pivotSearchWithTerms(srcNode, kind, scope, terms) {
  const body = el('div');
  body.appendChild(el('div', { class: 'hint', style: 'margin-bottom:8px' },
    'VirusTotal Intelligence query built from your selected attributes. Matching attributes ' +
    'use real search facets (e.g. registrar:, creation_date:); others fall back to free-text. ' +
    'Toggle terms, set date operators, or edit the query directly, then run. (Needs a premium key.)'));

  const qbox = el('textarea', { class: 'qbox mono', rows: 3, spellcheck: 'false',
    placeholder: 'entity:domain registrar:"…" last_update_date:2020-02-10+' });
  // Track whether the analyst has hand-edited the query away from what we built.
  // We compare against the last auto-generated value; programmatic rebuilds
  // (toggling terms) update that baseline so they don't count as edits.
  let autoQuery = '';
  let userEdited = false;
  function rebuild() { autoQuery = composeQuery(scope, terms); qbox.value = autoQuery; userEdited = false; updateEditNote(); }

  const list = el('div', { class: 'qterms' });
  terms.forEach(t => {
    const usable = t.kind !== 'skip';
    const row = el('label', { class: 'qterm' + (usable ? '' : ' disabled') });
    const cb = el('input', { type: 'checkbox' });
    cb.checked = t.enabled && usable; cb.disabled = !usable;
    cb.addEventListener('change', () => { t.enabled = cb.checked; rebuild(); });
    const cells = [cb, el('span', { class: 'qk' }, t.key)];
    if (t.kind === 'date') {
      const sel = el('select', { class: 'qop' });
      sel.append(el('option', { value: '+' }, 'on/after +'), el('option', { value: '-' }, 'on/before −'));
      sel.value = t.op;
      sel.addEventListener('change', () => { t.op = sel.value; rebuild(); });
      // stop the surrounding <label> from toggling the checkbox when using the select
      sel.addEventListener('click', ev => ev.preventDefault());
      cells.push(el('span', { class: 'qt mono' }, `${t.mod}:${t.dateVal}`), sel);
    } else {
      cells.push(el('span', { class: 'qt mono' }, t.term || '—'), el('span', { class: 'qn hint' }, t.note));
    }
    row.append(...cells);
    list.appendChild(row);
  });
  body.appendChild(list);

  body.appendChild(el('div', { class: 'section-label', style: 'margin:8px 0 4px' }, 'final VT query'));
  body.appendChild(qbox);
  // Small accent note shown ONLY once the query has been hand-edited, recording
  // which attributes the auto-query was built from (so a divergence is visible).
  const editNote = el('div', { class: 'qedit-note' });
  editNote.style.display = 'none';
  body.appendChild(editNote);
  function sourceAttrKeys() {
    return terms.filter(t => t.enabled && t.kind !== 'skip').map(t => t.key);
  }
  function updateEditNote() {
    if (userEdited) {
      const keys = sourceAttrKeys();
      editNote.textContent = 'edited — auto-query was built from: ' + (keys.length ? keys.join(', ') : '(no attributes)');
      editNote.style.display = '';
    } else {
      editNote.style.display = 'none';
    }
  }
  qbox.addEventListener('input', () => {
    userEdited = (qbox.value.trim() !== autoQuery.trim());
    updateEditNote();
  });

  rebuild();
  const status = el('div', { class: 'hint', style: 'margin-top:6px' });
  body.appendChild(status);

  openModal('VT query · pivot search', body, [
    { label: 'run search', primary: true, onClick: async () => {
        const q = qbox.value.trim();
        if (!q) { status.textContent = 'query is empty — enable a term or type one.'; return; }
        // If the analyst hand-edited the auto-built query, log the divergence:
        // the final query plus the attributes it was originally built from. This
        // is how we capture better facet mappings (e.g. the signature: fix) for
        // future improvement. Only logged when actually edited.
        if (userEdited) {
          logEditedQuery(q, autoQuery, sourceAttrKeys());
        }
        status.textContent = 'querying VirusTotal…';
        try {
          const data = await vtSearch(q);
          const items = (data && data.data) || [];
          closeModal();
          if (!items.length) { toast('no hits for: ' + q); return; }
          // Build a sub-entity that represents this pivot so new entities hang
          // off it: origin → (pivot sub) → each new entity.
          const activeTerms = terms.filter(t => t.enabled && (t.kind !== 'skip'));
          const subLabelText = activeTerms.map(t => t.kind === 'date' ? `${t.mod}:${t.dateVal}${t.op}` : (t.term || t.value)).join(' ');
          // attribute(s) that drove the pivot → used to name the "match - X" edge
          const attrLabel = activeTerms.map(t => (t.key || '').split('.')[0].replace(/\[\d+\]$/, '')).filter(Boolean).join('/') || 'pivot';
          const total = data && data.meta && (data.meta.total_hits ?? data.meta.count);
          showHits(srcNode, 'vt-search', items, q, { field: 'vt-pivot', value: subLabelText || q, attrLabel, pivotQuery: q, pivotKind: kind }, {
            total: typeof total === 'number' ? total : null,
            cursor: vtNextCursor(data),
            fetchMore: async (cur) => {
              const d = await vtSearch(q, 40, cur);
              return { items: (d && d.data) || [], cursor: vtNextCursor(d),
                       total: (d && d.meta && (d.meta.total_hits ?? d.meta.count)) };
            },
          });
        } catch (err) {
          if (/\b40[13]\b/.test(err.message))
            status.innerHTML = '<span class="mal">VT Intelligence search needs a premium key.</span> Try relationship “expand” instead.';
          else status.innerHTML = '<span class="mal">' + esc(err.message) + '</span>';
        }
      } },
    { label: 'copy query', onClick: () => { navigator.clipboard && navigator.clipboard.writeText(qbox.value); toast('query copied'); } },
    { label: 'cancel', onClick: () => closeModal() },
  ]);
}

/* ----- hits modal: checkboxes -> Next -> add as entities ----- */
function hitToEntity(rel, item) {
  // returns {kind, value, label, sub?} or null
  const t = item.type;
  const a = item.attributes || {};
  if (rel === 'resolutions' || t === 'resolution') {
    // resolution has ip_address + host_name; pick the "other" side
    if (a.ip_address && a.host_name) {
      return [{ kind: 'ip', value: a.ip_address }, { kind: 'domain', value: a.host_name }];
    }
  }
  if (t === 'file') return { kind: 'file', value: item.id, label: fileDisplayName(a, item.id) };
  if (t === 'domain') return { kind: 'domain', value: item.id };
  if (t === 'ip_address') return { kind: 'ip', value: item.id };
  if (t === 'url') return { kind: 'url', value: a.url || item.id };
  return null;
}
function showHits(srcEntity, rel, items, note = '', pivotSub = null, page = null) {
  // `page` (optional) enables pagination:
  //   { total: <number|null>, cursor: <string|null>, fetchMore: async (cursor) => ({items, cursor, total}) }
  // When present, we show how many total results VT reported and a "load more"
  // button that fetches the next page and APPENDS rows (so checkbox indices into
  // `items` stay valid). `items` is mutated as pages load.
  const fmtBytes = n => {
    if (n == null) return null;
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(0) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  };
  const fmtEpoch = s => (s ? new Date(s * 1000).toISOString().slice(0, 10) : null);
  const sigVendor = a => {
    const si = a.signature_info;
    if (!si) return null;
    if (typeof si.signers === 'string' && si.signers) return si.signers.split(';')[0].trim();
    if (Array.isArray(si.signers) && si.signers.length) return String(si.signers[0]).trim();
    return si['x509 subject'] || null;
  };
  // Build a {display, det} view for one VT item.
  const viewOf = it => {
    const a = it.attributes || {};
    let display = it.id;
    if (it.type === 'resolution') display = `${a.host_name || '?'} ↔ ${a.ip_address || '?'}`;
    else if (it.type === 'url') display = a.url || it.id;
    else if (it.type === 'file') display = fileDisplayName(a, it.id) + ' · ' + it.id;
    const det = [];
    if (it.type === 'file') {
      const v = sigVendor(a); if (v) det.push('signed: ' + v);
      const sz = fmtBytes(a.size); if (sz) det.push(sz);
      if (a.type_description) det.push(a.type_description);
    } else if (it.type === 'ip_address') {
      if (a.asn != null) det.push('AS' + a.asn);
      if (a.as_owner) det.push(a.as_owner);
    } else if (it.type === 'domain') {
      if (a.registrar) det.push(a.registrar);
      const cd = fmtEpoch(a.creation_date); if (cd) det.push('created ' + cd);
    }
    if (a.last_analysis_stats) det.push('mal ' + (a.last_analysis_stats.malicious ?? 0));
    if (a.reputation != null) det.push('rep ' + a.reputation);
    if (a.country && it.type !== 'ip_address') det.push(a.country);
    if (it.context_attributes && it.context_attributes.timestamp)
      det.push(new Date(it.context_attributes.timestamp * 1000).toISOString().slice(0, 10));
    return { display, det: det.join(' · ') };
  };

  let cursor = page ? page.cursor : null;
  const total = page ? page.total : null;

  const body = el('div');
  const summary = el('div', { class: 'hint', style: 'margin-bottom:8px' });
  body.appendChild(summary);
  const tbl = el('table', { class: 'hits' });
  // header "select all" starts CHECKED (rows default to checked too)
  const selAll = el('input', { type: 'checkbox' }); selAll.checked = true;
  selAll.addEventListener('change', ev => $$('input.hit', tbl).forEach(c => { c.checked = ev.target.checked; }));
  tbl.appendChild(el('tr', {}, [
    el('th', { class: 'cb' }, selAll),
    el('th', {}, 'type'), el('th', {}, 'indicator'), el('th', { class: 'ingraph-h', title: 'already in the graph' }, '✓?'),
    el('th', {}, 'detail') ]));
  body.appendChild(tbl);

  // Is the entity this hit maps to already present in the graph?
  function hitAlreadyInGraph(it) {
    const res = hitToEntity(rel, it);
    const list = Array.isArray(res) ? res : (res ? [res] : []);
    if (!list.length) return false;
    // for a multi-entity hit (resolution), consider it "in graph" only if all parts exist
    return list.every(m => !!state.G.entities[entityKey(m.kind, m.value)]);
  }

  // Append a row for items[idx] (idx is the index into the shared items array).
  function appendRow(idx) {
    const it = items[idx];
    const v = viewOf(it);
    const inGraph = hitAlreadyInGraph(it);
    const cb = el('input', { type: 'checkbox', class: 'hit' }); cb.checked = true; cb.dataset.i = idx;
    const badge = inGraph
      ? el('span', { class: 'ingraph-badge', title: 'already in the graph — adding will link to the existing entity, not duplicate it' }, 'in graph')
      : el('span', {});
    tbl.appendChild(el('tr', { class: inGraph ? 'is-ingraph' : '' }, [
      el('td', { class: 'cb' }, cb),
      el('td', {}, it.type),
      el('td', { class: 'mono' }, v.display),
      el('td', { class: 'ingraph-c' }, badge),
      el('td', { class: 'hint' }, v.det) ]));
  }
  items.forEach((_, i) => appendRow(i));

  // Pagination footer: count line + "load more" when there's a cursor.
  const pager = el('div', { class: 'hits-pager', style: 'margin-top:8px; display:flex; align-items:center; gap:10px' });
  body.appendChild(pager);
  const moreBtn = el('button', {}, 'load more');
  function refreshSummary() {
    const shown = items.length;
    const totTxt = (typeof total === 'number') ? ` of ${total}${total > shown && !cursor ? '+' : ''}` : (cursor ? '+' : '');
    summary.textContent = `${rel}${note ? ' · ' + note : ''} — showing ${shown}${totTxt} result(s). `
      + `Tick rows, then "add selected" to link them to “${shortLabel(srcEntity.kind, srcEntity.value)}”.`
      + (cursor ? ' More are available — use “load more”.' : '');
  }
  async function loadMore() {
    if (!cursor || !page || !page.fetchMore) return;
    moreBtn.disabled = true; moreBtn.textContent = 'loading…';
    try {
      const res = await page.fetchMore(cursor);
      const newItems = (res && res.items) || [];
      const start = items.length;
      newItems.forEach(it => items.push(it));
      for (let i = start; i < items.length; i++) appendRow(i);
      cursor = res ? res.cursor : null;
      refreshSummary(); updatePager();
    } catch (err) {
      toast('load more failed: ' + (err.message || err), true);
    } finally {
      moreBtn.disabled = false; moreBtn.textContent = 'load more';
    }
  }
  moreBtn.addEventListener('click', loadMore);
  function updatePager() {
    pager.innerHTML = '';
    if (cursor && page && page.fetchMore) {
      pager.append(moreBtn, el('span', { class: 'hint' }, `loaded ${items.length}${typeof total === 'number' ? ' / ' + total : ''}`));
    } else if (typeof total === 'number' && total > items.length) {
      // No cursor but VT said there are more (rare; e.g. relationship count > page)
      pager.append(el('span', { class: 'hint' }, `showing ${items.length} of ${total}; VT did not provide a next-page cursor`));
    }
  }
  refreshSummary(); updatePager();

  openModal(`hits · ${rel}`, body, [
    { label: 'add selected', primary: true, onClick: () => {
        let created = 0, linked = 0;
        let pivotSubId = null;
        if (pivotSub) {
          pivotSubId = addSub(srcEntity.id, pivotSub.field, pivotSub.value);
          // Remember the VT pivot query on the sub so it can be re-run later
          // straight from the sub-entity (see openSubDrawer's "re-run pivot").
          if (pivotSubId && pivotSub.pivotQuery && state.G.subs[pivotSubId]) {
            const sub = state.G.subs[pivotSubId];
            sub.pivotQuery = pivotSub.pivotQuery;
            sub.pivotKind = pivotSub.pivotKind || null;
          }
        }
        $$('input.hit:checked', tbl).forEach(c => {
          const it = items[Number(c.dataset.i)];
          const res = hitToEntity(rel, it);
          const list = Array.isArray(res) ? res : (res ? [res] : []);
          let prev = srcEntity.id;
          list.forEach((m, idx) => {
            // Link to the existing node if this indicator is already in the graph
            // (addEntity returns the existing one — no duplicate is created).
            const existed = !!state.G.entities[entityKey(m.kind, m.value)];
            const ne = addEntity(m.kind, m.value, { silent: true });
            if (!ne) return;
            if (m.label && entName(ne) === ne.value) {
              ne.name = m.label;
              if (state.cy) state.cy.$id(ne.id).data('label', KIND[ne.kind].glyph + ' ' + entShort(ne));
            }
            if (idx === 0) {
              if (pivotSubId) addEdge(pivotSubId, ne.id, pivotSub.attrLabel ? `match - ${pivotSub.attrLabel}` : 'match', 'rel');
              else addEdge(srcEntity.id, ne.id, rel);
            } else {
              addEdge(prev, ne.id, 'resolves');
            }
            prev = ne.id; existed ? linked++ : created++;
          });
        });
        closeModal();
        const total = created + linked;
        if (total) {
          relayoutSoft();
          const parts = [];
          if (created) parts.push(`${created} added`);
          if (linked) parts.push(`${linked} linked to existing`);
          toast(parts.join(' · '));
        } else toast('nothing selected', true);
        if (page && typeof page.onAdded === 'function') { try { page.onAdded(); } catch (e) {} }
      } },
    { label: 'cancel', onClick: closeModal },
  ]);
}
// Incremental, position-preserving layout. Existing (already-placed) nodes are
// locked so the established graph doesn't jump around; only newly-added nodes
// are positioned (seeded near their neighbours, then relaxed with the locked
// nodes acting as fixed anchors). This is what runs after pivots/adds so you
// can actually see where new entities landed. Use relayout() for a full
// re-flow when you explicitly want one.
// Incremental placement for newly-added nodes. Principle (operator's choice):
// adding entities should INCREASE visibility, not re-cluster. New nodes are
// dropped into OPEN SPACE, pushed AWAY from the existing graph's centre, near
// their connecting neighbour but biased outward so the new edge stays readable.
// Nothing already on the canvas moves, and there is NO force-directed pass —
// only the explicit "re-layout" button imposes clumping. The user stays fully
// in charge of what ends up grouped where.
function relayoutSoft() {
  if (!state.cy) return;
  const cy = state.cy;
  const fresh = cy.nodes().filter(n => !n.data('_placed'));
  if (fresh.length === 0) return;
  const placed = cy.nodes().filter(n => n.data('_placed'));
  const { ideal } = layoutSpacing();
  const STEP = Math.max(90, ideal);          // spacing between dropped nodes

  // existing graph extent + centre (to push new nodes outward from it)
  let cx = 0, cy0 = 0, minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  if (placed.length) {
    placed.forEach(n => { const p = n.position(); cx += p.x; cy0 += p.y; minX = Math.min(minX, p.x); minY = Math.min(minY, p.y); maxX = Math.max(maxX, p.x); maxY = Math.max(maxY, p.y); });
    cx /= placed.length; cy0 /= placed.length;
  } else {
    // empty canvas: just lay the new nodes on a tidy grid around origin
    cx = 0; cy0 = 0; minX = -STEP; maxX = STEP; minY = -STEP; maxY = STEP;
  }
  const occupied = placed.map(n => n.position());

  // does a candidate point collide with any node we know about?
  const tooClose = (x, y, extra) => {
    for (const p of occupied) { if (Math.abs(p.x - x) < STEP && Math.abs(p.y - y) < STEP) return true; }
    for (const p of extra) { if (Math.abs(p.x - x) < STEP && Math.abs(p.y - y) < STEP) return true; }
    return false;
  };
  // spiral outward from a target until we find clear space
  function findOpen(tx, ty, extra) {
    if (!tooClose(tx, ty, extra)) return { x: tx, y: ty };
    let r = STEP, ang = Math.random() * Math.PI * 2;
    for (let i = 0; i < 400; i++) {
      const x = tx + Math.cos(ang) * r, y = ty + Math.sin(ang) * r;
      if (!tooClose(x, y, extra)) return { x, y };
      ang += 2.399963;                       // golden-angle scatter
      r += STEP * 0.18;
    }
    return { x: tx + (Math.random() - 0.5) * STEP * 6, y: ty + (Math.random() - 0.5) * STEP * 6 };
  }

  const placedNew = [];
  // periphery angle cursor for nodes that have no placed neighbour
  let peripheryAng = Math.random() * Math.PI * 2;
  const radius = Math.max(maxX - minX, maxY - minY) / 2 + STEP * 2.2;

  fresh.forEach(n => {
    const anchor = n.neighborhood('node[?_placed]').first();
    let target;
    if (anchor && anchor.nonempty()) {
      // place on the OUTWARD side of the neighbour: vector centre→anchor, extended
      const ap = anchor.position();
      let vx = ap.x - cx, vy = ap.y - cy0;
      const len = Math.hypot(vx, vy) || 1;
      vx /= len; vy /= len;
      target = { x: ap.x + vx * STEP * 1.6, y: ap.y + vy * STEP * 1.6 };
    } else {
      // no connection to the existing graph → drop it on the periphery, in space
      target = { x: cx + Math.cos(peripheryAng) * radius, y: cy0 + Math.sin(peripheryAng) * radius };
      peripheryAng += 2.399963;
    }
    const pos = findOpen(target.x, target.y, placedNew);
    n.position(pos);
    placedNew.push(pos);
    n.data('_placed', true);
  });

  // bring the new arrivals into view without disturbing existing positions
  try { cy.animate({ fit: { eles: fresh.union(fresh.neighborhood()), padding: 80 }, duration: 350 }); } catch (e) {}
}

/* ============================ modal helper ============================== */
function openModal(title, bodyNode, buttons = []) {
  $('#modalTitle').textContent = title;
  const mb = $('#modalBody'); mb.innerHTML = ''; mb.appendChild(bodyNode);
  const mf = $('#modalFoot'); mf.innerHTML = '';
  mf.appendChild(el('span', { class: 'spacer' }));
  buttons.forEach(b => mf.appendChild(el('button',
    { class: b.primary ? 'primary' : '', onclick: b.onClick }, b.label)));
  $('#overlay').classList.add('open');
}
function closeModal() { $('#overlay').classList.remove('open'); }

/* ============================ entity list =============================== */
function selectEntity(id, fromList) {
  if (!state.cy) return;
  state.cy.$('node:selected').unselect();
  state.cy.$id(id).select();
  renderEntityList();
  if (fromList) { state.cy.animate({ center: { eles: state.cy.$id(id) }, zoom: Math.max(state.cy.zoom(), 1) }, { duration: 250 }); }
}
function renderEntityList() {
  const wrap = $('#entityList'); wrap.innerHTML = '';
  const byKind = { file: [], domain: [], ip: [], url: [] };
  Object.values(state.G.entities).forEach(e => byKind[e.kind].push(e));
  const sel = state.cy ? state.cy.$('node:selected').id() : null;
  Object.keys(byKind).forEach(k => {
    const items = byKind[k]; if (!items.length) return;
    const open = LS.get('iochub.grp.' + k, true);
    const head = el('div', { class: 'g-head', onclick: () => {
      LS.set('iochub.grp.' + k, !open); renderEntityList(); } }, [
      el('span', { class: 'tw' }, open ? '▾' : '▸'),
      el('span', {}, KIND[k].glyph + ' ' + KIND[k].label),
      el('span', { class: 'cnt' }, '(' + items.length + ')') ]);
    const box = el('div', { class: 'g-items' });
    if (open) items.sort((a, b) => entName(a).localeCompare(entName(b))).forEach(e => {
      const renamed = entName(e) !== e.value;
      const nameEl = el('span', {
        class: 'txt', title: 'click again or double-click to rename',
        onclick: ev => {
          ev.stopPropagation();
          if (e.id === (state.cy ? state.cy.$('node:selected').id() : null)) startRename(e, nameEl);
          else selectEntity(e.id, true);
        },
        ondblclick: ev => { ev.stopPropagation(); startRename(e, nameEl); },
      }, entName(e));
      box.appendChild(el('div', {
        class: 'ent-item' + (e.id === sel ? ' sel' : ''),
        onclick: () => selectEntity(e.id, true),
        oncontextmenu: ev => { ev.preventDefault(); entityContextMenu(e, ev.clientX, ev.clientY); },
        title: e.value,
      }, [
        el('span', { class: 'glyph' }, KIND[k].glyph),
        el('span', { class: 'ent-main' }, [
          nameEl,
          // Always keep the canonical indicator visible once a custom name is set,
          // so it's clear what links this node across enrichments.
          renamed ? el('span', { class: 'ent-ind' }, e.value) : null,
        ]),
        e.malicious ? el('span', { class: 'mal' }, '●') : null,
      ]));
    });
    wrap.append(el('div', { class: 'group' }, [head, box]));
  });
  if (!Object.values(state.G.entities).length)
    wrap.appendChild(el('div', { class: 'hint' }, 'No entities yet. Add one above.'));
}

// Swap an entity's name label for an inline editor. The canonical indicator
// (e.value) is never touched, so renaming is purely cosmetic and the node stays
// linked across enrichments.
function startRename(e, holder) {
  const input = el('input', { class: 'rename-input', value: entName(e), spellcheck: 'false' });
  holder.replaceWith(input);
  input.focus(); input.select();
  let done = false;
  const commit = save => {
    if (done) return; done = true;
    if (save) {
      const v = input.value.trim();
      e.name = v || e.value;            // empty -> reset to the indicator
    }
    if (state.cy) { const n = state.cy.$id(e.id); if (n) n.data('label', KIND[e.kind].glyph + ' ' + entShort(e)); }
    if (state.drawerEntity === e.id) renderDrawerHead(e);
    renderEntityList();
  };
  input.addEventListener('keydown', ev => {
    if (ev.key === 'Enter') { ev.preventDefault(); commit(true); }
    else if (ev.key === 'Escape') { ev.preventDefault(); commit(false); }
  });
  input.addEventListener('blur', () => commit(true));
}
function updateStatus() {
  $('#stEnt').textContent = Object.keys(state.G.entities).length;
  $('#stSub').textContent = Object.keys(state.G.subs).length;
  $('#stRel').textContent = Object.keys(state.G.edges).length;
  $('#graphCount').textContent =
    `${Object.keys(state.G.entities).length} entities · ${Object.keys(state.G.subs).length} subs`;
  // Any status change reflects a graph mutation → schedule a debounced autosave,
  // unless we're mid-load or just cleared the graph (handled by the flag).
  if (!state._suppressAutosave) autosaveDirty();
}

/* ===================== storage slots (server, encrypted) ===============
   Slots 1 & 2 are the user's two manual graphs; slot 3 is the AUTOSAVE slot,
   written automatically after 3s of inactivity (or on tab-switch). All live on
   the backend as AES-GCM ciphertext; plaintext exists only in the browser. */
const AUTOSAVE_SLOT = 3;
const MANUAL_SLOTS = [1, 2];
function loggedIn() { return !!state.token && !!state.encKey; }

async function refreshSlots() {
  state.slotMeta = state.slotMeta || {};
  if (!loggedIn()) { renderSlots(); return; }
  try {
    const list = await apiCall('/api/graphs');         // {slots:[..], max}
    const filled = new Set((list.slots || []).map(Number));
    for (const n of [AUTOSAVE_SLOT, ...MANUAL_SLOTS]) {
      if (!filled.has(n)) { state.slotMeta[n] = null; continue; }
      try {
        const env = await apiCall('/api/graphs/' + n);
        const g = await decryptObj(env);
        state.slotMeta[n] = g ? { entities: Object.keys(g.entities || {}).length, saved: g.meta?.saved } : { entities: 0 };
      } catch (e) { state.slotMeta[n] = { error: true }; }
    }
  } catch (e) { /* offline: leave as-is */ }
  renderSlots();
}
function renderSlots() {
  const wrap = $('#slots'); wrap.innerHTML = '';
  if (!loggedIn()) {
    wrap.appendChild(el('div', { class: 'hint' }, 'Log in (top bar → connect…) to load your encrypted graphs.'));
    return;
  }
  const meta = state.slotMeta || {};

  // --- autosave slot (above slot 1) ---
  const am = meta[AUTOSAVE_SLOT];
  const auto = el('div', { class: 'slot autosave' + (state.activeSlot === AUTOSAVE_SLOT ? ' active' : '') });
  auto.append(el('div', { class: 'sl-head' }, [
    el('span', { class: 'name' }, '⟳ autosave'),
    el('span', { class: 'hint', id: 'autosaveState' },
      state._autosaving ? 'saving…' : (am && !am.error ? 'auto' : (am && am.error ? 'decrypt error' : 'empty'))) ]));
  auto.append(el('div', { class: 'sl-meta' }, am && !am.error
    ? `${am.entities} entities${am.saved ? ' · ' + new Date(am.saved).toLocaleTimeString() : ''}`
    : (am && am.error ? 'cannot decrypt with this session key' : 'saves automatically after 3s idle')));
  const aacts = el('div', { class: 'sl-actions' });
  aacts.append(
    el('button', { onclick: () => doAutosave(true), title: 'Save a snapshot to the autosave slot now' }, 'save now'),
    el('button', { onclick: () => loadSlot(AUTOSAVE_SLOT), disabled: !am || am.error }, 'load'),
    el('button', { onclick: () => downloadSlot(AUTOSAVE_SLOT), disabled: !am || am.error }, 'download'));
  auto.append(aacts);
  wrap.appendChild(auto);

  // --- the two manual graph slots ---
  MANUAL_SLOTS.forEach(n => {
    const m = meta[n];
    const card = el('div', { class: 'slot' + (state.activeSlot === n ? ' active' : '') });
    card.append(el('div', { class: 'sl-head' }, [
      el('span', { class: 'name' }, 'slot ' + n),
      el('span', { class: 'hint' }, m ? (m.error ? 'decrypt error' : 'graph') : 'empty') ]));
    card.append(el('div', { class: 'sl-meta' }, m && !m.error
      ? `${m.entities} entities${m.saved ? ' · saved ' + new Date(m.saved).toLocaleString() : ''}`
      : (m && m.error ? 'cannot decrypt with this session key' : 'no graph stored')));
    const acts = el('div', { class: 'sl-actions' });
    acts.append(
      el('button', { onclick: () => saveToSlot(n) }, 'save here'),
      el('button', { onclick: () => loadSlot(n), disabled: !m || m.error }, 'load'),
      el('button', { onclick: () => downloadSlot(n), disabled: !m || m.error }, 'download'),
      el('button', { onclick: () => replaceSlot(n) }, 'replace…'));
    card.append(acts);
    wrap.appendChild(card);
  });

  // --- current graph (local save/load; works even if the server upload fails) ---
  const cur = el('div', { class: 'slot current' });
  const n = Object.keys(state.G.entities || {}).length;
  cur.append(el('div', { class: 'sl-head' }, [
    el('span', { class: 'name' }, '▤ current graph'),
    el('span', { class: 'hint' }, n + ' entities') ]));
  cur.append(el('div', { class: 'sl-meta' }, 'save the working graph to a local file — use this if a graph is too large to upload'));
  const cacts = el('div', { class: 'sl-actions' });
  cacts.append(
    el('button', { onclick: () => downloadCurrentGraph() }, 'save to file'),
    el('button', { onclick: () => loadCurrentGraphFromFile() }, 'load from file'));
  cur.append(cacts);
  wrap.appendChild(cur);
}
async function saveToSlot(n) {
  if (!loggedIn()) { toast('Log in first (top bar → connect…).', true); return; }
  try {
    state.G.meta.saved = Date.now();
    const env = await encryptObj(serializeGraph());
    await apiCall('/api/graphs/' + n, { method: 'PUT', body: env });
    state.activeSlot = n;
    toast(`graph encrypted & saved to slot ${n}`);
    refreshSlots();
  } catch (e) { toast('save failed: ' + e.message, true); }
}

/* ----- autosave (server-side, slot 3) -----
   After any graph change we wait for 3s of inactivity, then encrypt + upload the
   graph to the autosave slot. Switching away from the tab flushes immediately so
   nothing is lost when you leave. Autosave is silent (no toasts) and never
   touches the user's two manual slots. */
let _autosaveTimer = null;
function autosaveDirty() {
  if (!loggedIn()) return;                 // nothing to save / can't encrypt
  if (_autosaveTimer) clearTimeout(_autosaveTimer);
  _autosaveTimer = setTimeout(() => { _autosaveTimer = null; doAutosave(false); }, 3000);
}
async function doAutosave(manual) {
  if (!loggedIn()) { if (manual) toast('Log in first (top bar → connect…).', true); return; }
  if (state._autosaving) return;           // don't overlap saves
  // Skip empty graphs unless the user explicitly clicked "save now".
  const count = Object.keys(state.G.entities || {}).length;
  if (!manual && count === 0) return;
  state._autosaving = true;
  const ind = $('#autosaveState'); if (ind) ind.textContent = 'saving…';
  try {
    state.G.meta.saved = Date.now();
    const env = await encryptObj(serializeGraph());
    await apiCall('/api/graphs/' + AUTOSAVE_SLOT, { method: 'PUT', body: env });
    if (state.slotMeta) state.slotMeta[AUTOSAVE_SLOT] = { entities: count, saved: state.G.meta.saved };
    renderSlots();
    if (manual) toast('snapshot saved to autosave slot');
  } catch (e) {
    const tooBig = /too large|413|body/i.test(e.message || '');
    if (manual || tooBig) {
      toast('autosave failed' + (e.message ? ': ' + e.message : '') +
        (tooBig ? ' — use “current graph → save to file” to keep it locally.' : ''), true);
    }
    const ind2 = $('#autosaveState'); if (ind2) ind2.textContent = tooBig ? 'too large — save locally' : 'save failed';
  } finally {
    state._autosaving = false;
  }
}
// Flush a pending autosave when the tab is hidden/switched, so leaving the tab
// doesn't drop the debounced save.
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden' && _autosaveTimer) {
    clearTimeout(_autosaveTimer); _autosaveTimer = null; doAutosave(false);
  }
});
async function loadSlot(n) {
  if (!loggedIn()) return;
  try {
    const env = await apiCall('/api/graphs/' + n);
    const g = await decryptObj(env);
    if (!g) { toast('slot ' + n + ' is empty', true); return; }
    loadGraph(g); state.activeSlot = n; renderSlots();
    toast(`loaded slot ${n}`);
  } catch (e) { toast('load failed (wrong session key?): ' + e.message, true); }
}
async function downloadSlot(n) {
  if (!loggedIn()) return;
  try {
    const env = await apiCall('/api/graphs/' + n);
    const g = await decryptObj(env);
    if (!g) { toast('slot ' + n + ' is empty', true); return; }
    const blob = new Blob([JSON.stringify(g, null, 2)], { type: 'application/json' });
    const a = el('a', { href: URL.createObjectURL(blob), download: `iochub-slot${n}.json` });
    document.body.appendChild(a); a.click(); a.remove();
    toast('decrypted graph downloaded');
  } catch (e) { toast('download failed: ' + e.message, true); }
}

// Save the CURRENT in-memory graph straight to a local file (no server). This
// is the fallback when a graph is too large to upload — work is never lost.
function downloadCurrentGraph() {
  try {
    const g = serializeGraph();
    const blob = new Blob([JSON.stringify(g, null, 2)], { type: 'application/json' });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const a = el('a', { href: URL.createObjectURL(blob), download: `iochub-graph-${stamp}.json` });
    document.body.appendChild(a); a.click(); a.remove();
    const n = Object.keys(state.G.entities || {}).length;
    toast(`current graph saved locally (${n} entities)`);
  } catch (e) { toast('local save failed: ' + e.message, true); }
}
// Load a graph from a local file into the current view (no server needed).
function loadCurrentGraphFromFile() {
  const inp = el('input', { type: 'file', accept: '.json,application/json' });
  inp.addEventListener('change', () => {
    const f = inp.files[0]; if (!f) return;
    const rd = new FileReader();
    rd.onload = () => {
      try { loadGraph(JSON.parse(rd.result)); toast('graph loaded from file'); }
      catch (e) { toast('load failed: ' + e.message, true); }
    };
    rd.readAsText(f);
  });
  inp.click();
}
function replaceSlot(n) {
  if (!loggedIn()) { toast('Log in first (top bar → connect…).', true); return; }
  const inp = el('input', { type: 'file', accept: '.json,application/json' });
  inp.addEventListener('change', () => {
    const f = inp.files[0]; if (!f) return;
    const rd = new FileReader();
    rd.onload = async () => {
      try {
        const g = JSON.parse(rd.result);
        const env = await encryptObj(g);
        await apiCall('/api/graphs/' + n, { method: 'PUT', body: env });
        toast(`slot ${n} replaced (encrypted) from file`); refreshSlots();
      } catch (e) { toast('replace failed: ' + e.message, true); }
    };
    rd.readAsText(f);
  });
  inp.click();
}
function serializeGraph() {
  // capture positions from cytoscape
  const positions = {};
  if (state.cy) state.cy.nodes().forEach(nd => { positions[nd.id()] = nd.position(); });
  return JSON.parse(JSON.stringify({ ...state.G, positions, meta: { ...state.G.meta } }));
}
function loadGraph(g) {
  state._suppressAutosave = true;        // loading isn't a user edit
  state.G = blankGraph();
  state.G.meta = g.meta || state.G.meta;
  if (state.cy) state.cy.elements().remove();
  Object.values(g.entities || {}).forEach(e => { state.G.entities[e.id] = e; });
  Object.values(g.subs || {}).forEach(s => { state.G.subs[s.id] = s; });
  // recreate cy nodes with positions
  const pos = g.positions || {};
  Object.values(state.G.entities).forEach(e => {
    state.cy.add({ group: 'nodes', data: cyNodeData(e),
      position: pos[e.id] || nearStart(), classes: 'entity ' + e.kind + (e.malicious ? ' mal' : '') });
  });
  Object.values(state.G.subs).forEach(s => {
    const node = state.cy.add({ group: 'nodes', data: { id: s.id, label: subLabel(s), sub: true },
      position: pos[s.id] || nearStart(), classes: 'sub' + (s.collapsed ? ' collapsed' : '') });
    if (!state.settings.showSubs) node.style('display', 'none');
  });
  Object.values(g.edges || {}).forEach(ed => { state.G.edges[ed.id] = ed; cyAddEdge(ed); });
  // Resume any CAPE jobs that were in flight (node marks + background poller).
  Object.values(state.G.entities).forEach(e => { if (e.cape) markCapeNode(e); });
  if (Object.values(state.G.entities).some(e => e.cape && e.cape.status === 'running')) startCapePoller();
  state.cy.nodes().forEach(n => n.data('_placed', true));   // loaded layout is the baseline
  renderEntityList(); updateStatus(); state.cy.fit(undefined, 40);
  state._suppressAutosave = false;       // edits from here on autosave normally
}
function newGraph() {
  if (!confirm('Clear the current graph? (save it to a slot first if you want to keep it)')) return;
  state.G = blankGraph();
  if (state.cy) state.cy.elements().remove();
  state.activeSlot = null; renderEntityList(); updateStatus(); renderSlots(); closeDrawer();
}

/* ============================ XLSX export =============================== */
// Which attribute keys were USED to form connections/pivots in the graph?
// Signals: edge labels of the form "match - <attr>" (attribute pivots), and the
// fields of sub-entities (which are created from attributes / relationships).
function usedConnectionAttrKeys() {
  const used = new Set();
  Object.values(state.G.edges).forEach(ed => {
    const m = /^match - (.+)$/.exec(ed.label || '');
    if (m) used.add(m[1].trim());
  });
  Object.values(state.G.subs).forEach(s => { if (s.field) used.add(s.field); });
  return used;
}
// Cell value for export: bare Unix timestamps become ISO dates (matching the UI).
function xlsxCell(v) {
  if (v === undefined || v === null) return '';
  const iso = maybeIsoDate(v);
  return iso || String(v);
}
// Per-kind columns that should come FIRST (after the general info), in this
// exact order, before the pivot-attributes and then the remaining attributes.
// Files lead with every hash, then meaningful_name; IPs with as_owner/asn/whois;
// domains with registrar/whois. URLs have no forced lead (left as-is).
const XLSX_LEAD = {
  file: ['md5', 'sha1', 'sha256', 'sha512', 'ssdeep', 'tlsh', 'vhash', 'imphash', 'authentihash', 'permhash', 'symhash', 'telfhash', 'meaningful_name'],
  ip: ['as_owner', 'asn', 'whois'],
  domain: ['registrar', 'whois'],
  url: [],
};
function exportXlsx() {
  const ents = Object.values(state.G.entities);
  if (!ents.length) { toast('nothing to export', true); return; }
  const wb = XLSX.utils.book_new();
  const usedKeys = usedConnectionAttrKeys();
  ['file', 'domain', 'ip', 'url'].forEach(kind => {
    const rows = ents.filter(e => e.kind === kind);
    if (!rows.length) return;
    // union of all attribute keys actually present for this type
    const keys = new Set();
    rows.forEach(e => Object.keys(e.attributes).forEach(k => keys.add(k)));
    const allAttrs = Array.from(keys);
    const matchKey = k => usedKeys.has(k) || [...usedKeys].some(u => k === u || k.startsWith(u + '.') || k.endsWith('.' + u));

    // 1) forced lead columns for this kind (only those that exist), in order
    const lead = (XLSX_LEAD[kind] || []).filter(k => keys.has(k));
    const taken = new Set(lead);
    // 2) attributes used for pivots/connections (not already in lead)
    const connAttrs = allAttrs.filter(k => !taken.has(k) && matchKey(k)).sort();
    connAttrs.forEach(k => taken.add(k));
    // 3) everything else, sorted
    const restAttrs = allAttrs.filter(k => !taken.has(k)).sort();

    const general = ['indicator', 'malicious', 'enriched'];
    const cols = [...general, ...lead, ...connAttrs, ...restAttrs];
    const aoa = [cols];
    rows.forEach(e => {
      aoa.push(cols.map(c => {
        if (c === 'indicator') return e.value;
        if (c === 'malicious') return e.malicious ? 'yes' : 'no';
        if (c === 'enriched') return e.enriched ? 'yes' : 'no';
        return xlsxCell(e.attributes[c]);
      }));
    });
    const ws = XLSX.utils.aoa_to_sheet(aoa);
    XLSX.utils.book_append_sheet(wb, ws, kind.toUpperCase() + 'S');
  });
  // relations sheet
  const rel = [['source', 'relation', 'target', 'type']];
  Object.values(state.G.edges).forEach(ed => {
    const s = state.G.entities[ed.source], t = state.G.entities[ed.target] || state.G.subs[ed.target];
    rel.push([s ? s.value : ed.source, ed.label,
      t ? (t.value ?? t.field + '=' + t.value) : ed.target, ed.kind]);
  });
  XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(rel), 'RELATIONS');
  XLSX.writeFile(wb, `iochub-export-${new Date().toISOString().slice(0, 10)}.xlsx`);
  toast('exported xlsx — general info, then pivot/connection attributes, then the rest');
}

/* ============================ MISP export ==============================
   Produce a MISP event JSON (the standard import/interchange format). Like
   AnyRun's MISP export, files become MISP "file" OBJECTS bundling their hashes
   + filename(s); domains/IPs/URLs become simple, well-typed attributes. We
   deliberately export ONLY the meaningful indicator fields per type — not the
   full attribute dump — so the event is clean threat-intel, not noise. */
function downloadJson(obj, filename) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const a = el('a', { href: URL.createObjectURL(blob), download: filename });
  document.body.appendChild(a); a.click(); a.remove();
}
function mispUuid() {
  // RFC-4122 v4, browser crypto if available
  if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}
function exportMisp() {
  const ents = Object.values(state.G.entities);
  if (!ents.length) { toast('nothing to export', true); return; }
  const nowS = Math.floor(Date.now() / 1000).toString();
  const Attribute = [];   // event-level attributes (domains, ips, urls)
  const Object_ = [];     // MISP objects (one "file" object per file entity)

  // hash attribute keys we recognise on a file, mapped to MISP attribute types
  const FILE_HASHES = { md5: 'md5', sha1: 'sha1', sha256: 'sha256', sha512: 'sha512',
    ssdeep: 'ssdeep', tlsh: 'tlsh', imphash: 'imphash', vhash: 'vhash',
    authentihash: 'authentihash', telfhash: 'telfhash', permhash: 'permhash' };

  ents.forEach(e => {
    const a = e.attributes || {};
    if (e.kind === 'file') {
      // a MISP "file" object: hashes + filename(s). The entity value is itself a
      // hash (sha256 in our model) — include it, plus any other hash attributes.
      const objAttrs = [];
      const seen = new Set();
      const pushHash = (rel, type, val) => { if (val && !seen.has(type + ':' + val)) { seen.add(type + ':' + val); objAttrs.push({ type, object_relation: rel, value: String(val), to_ids: true }); } };
      // entity value: detect which hash by length, default sha256
      const ev = String(e.value);
      const evType = ev.length === 32 ? 'md5' : ev.length === 40 ? 'sha1' : ev.length === 128 ? 'sha512' : 'sha256';
      pushHash(evType, evType, ev);
      Object.entries(FILE_HASHES).forEach(([k, type]) => { if (a[k]) pushHash(type, type, a[k]); });
      // filenames: meaningful_name + names[]
      const names = new Set();
      if (a.meaningful_name) names.add(String(a.meaningful_name));
      Object.keys(a).filter(k => /^names(\[\d+\])?$/.test(k)).forEach(k => { if (a[k]) names.add(String(a[k])); });
      if (a['_local.filename']) names.add(String(a['_local.filename']));
      [...names].forEach(n => objAttrs.push({ type: 'filename', object_relation: 'filename', value: n, to_ids: false }));
      if (objAttrs.length) {
        Object_.push({ name: 'file', 'meta-category': 'file', description: 'File object',
          template_uuid: '688c46fb-5edb-40a3-8273-1af7923e2215', template_version: '24',
          uuid: mispUuid(), timestamp: nowS, Attribute: objAttrs });
      }
    } else if (e.kind === 'domain') {
      Attribute.push({ type: 'domain', category: 'Network activity', value: String(e.value), to_ids: true, timestamp: nowS });
    } else if (e.kind === 'ip') {
      Attribute.push({ type: 'ip-dst', category: 'Network activity', value: String(e.value), to_ids: true, timestamp: nowS });
    } else if (e.kind === 'url') {
      Attribute.push({ type: 'url', category: 'Network activity', value: String(e.value), to_ids: true, timestamp: nowS });
    }
  });

  const event = {
    Event: {
      uuid: mispUuid(),
      info: `IoCHub export ${new Date().toISOString().slice(0, 10)}`,
      date: new Date().toISOString().slice(0, 10),
      threat_level_id: '4',          // 4 = undefined
      analysis: '0',                 // 0 = initial
      distribution: '0',             // your org only — safe default
      timestamp: nowS,
      Attribute,
      Object: Object_,
      Tag: [{ name: 'tlp:amber' }, { name: 'source:IoCHub' }],
    },
  };
  const counts = `${Object_.length} file object(s), ${Attribute.length} network attribute(s)`;
  downloadJson(event, `iochub-misp-${new Date().toISOString().slice(0, 10)}.json`);
  toast(`exported MISP event — ${counts}`);
}

/* ============================ CAPE sandbox ============================= */
const sleep = ms => new Promise(r => setTimeout(r, ms));

// CAPE is asynchronous: submit returns a job id immediately, the backend keeps
// polling its sandbox, and the browser is free to do other things. We track
// running jobs on the entities themselves (so they survive drawer close / graph
// save) and a single background poller updates them and notifies on completion.
async function detonateCape(e) {
  if (!state.token) { toast('Log in to the backend first (top bar → connect…).', true); return; }
  if (e.kind !== 'file') return;
  if (e.cape && e.cape.status === 'running') { toast('CAPE is already running for this file — you can keep working; it will update when done.'); return; }
  // Prefer locally cached bytes (don't auto-download from VT just to detonate;
  // CAPE can look the hash up itself). If CAPE has no record, we fall back to a
  // VT download below and resubmit the bytes.
  let blob = await loadSample(e.value);
  try {
    busy(true, 'CAPE: submitting…');
    const submitOnce = async (b) => apiCall('/api/cape/submit', { method: 'POST',
      body: b ? { filename: b.name, content_b64: b.b64 } : { sha256: e.value } });
    let sub = await submitOnce(blob);

    if (sub.status === 'disabled')     { toast('CAPE is disabled on the backend (set enabled = true in cape.conf).', true); return; }
    if (sub.status === 'unconfigured') { toast(sub.detail || 'CAPE is enabled but not set up on this server yet.', true); return; }
    if (sub.status === 'not_found') {
      // No existing CAPE analysis and we submitted only a hash — try to obtain
      // the bytes from VirusTotal, then resubmit for a real detonation.
      if (!blob) {
        const fetched = await getSampleBytes(e);   // VT download (needs privileged key)
        if (fetched) { blob = fetched; sub = await submitOnce(blob); }
      }
      if (sub.status === 'not_found') {
        toast('No existing CAPE analysis and no sample bytes available (upload the file, or use a privileged VT key to fetch it).', true);
        return;
      }
    }
    if (sub.status === 'error' || !sub.job_id) { toast('CAPE: ' + (sub.detail || 'submit failed'), true); return; }

    e.cape = { job_id: sub.job_id, status: 'running', started: Date.now() };
    e.cape._task = startTask('cape-detonate', shortLabel(e.kind, e.value) + ' · running', e.id);
    markCapeNode(e);
    if (state.drawerEntity === e.id) renderDrawerActions(e);
    toast('CAPE detonation started — you can keep working on the graph; the file will update when it finishes.');
    startCapePoller();
  } catch (err) { toast(err.message, true); }
  finally { busy(false); }
}

function markCapeNode(e) {
  if (!state.cy) return;
  const n = state.cy.$id(e.id);
  n.removeClass('cape-running cape-done');
  if (e.cape && e.cape.status === 'running') n.addClass('cape-running');
  else if (e.cape && e.cape.status === 'reported') n.addClass('cape-done');
}

function startCapePoller() {
  if (state._capeTimer) return;
  state._capeTimer = setInterval(capeTick, 8000);
  capeTick();
}
async function capeTick() {
  const running = Object.values(state.G.entities).filter(e => e.cape && e.cape.status === 'running' && e.cape.job_id);
  if (!running.length) { clearInterval(state._capeTimer); state._capeTimer = null; return; }
  for (const e of running) {
    let j;
    try { j = await apiCall('/api/cape/job/' + encodeURIComponent(e.cape.job_id)); }
    catch (err) { continue; } // transient; try again next tick
    const st = (j.status || '').split(':')[0];
    if (st === 'reported') {
      e.cape.status = 'reported';
      e.cape.indicators = j.indicators || {};
      markCapeNode(e);
      if (state.drawerEntity === e.id) renderDrawerActions(e);
      const n = (j.indicators ? ((j.indicators.domains||[]).length + (j.indicators.ips||[]).length + (j.indicators.urls||[]).length + (j.indicators.dropped||[]).length) : 0);
      if (e.cape._task) { e.cape._task.done(`${shortLabel(e.kind, e.value)} · ${n} IoCs`); e.cape._task = null; }
      toast(`CAPE finished for ${shortLabel(e.kind, e.value)} — ${n} IoC(s). Open the file to add them.`);
    } else if (st === 'failed' || st === 'error' || st === 'unknown') {
      e.cape.status = st;
      e.cape.detail = j.detail || st;
      markCapeNode(e);
      if (state.drawerEntity === e.id) renderDrawerActions(e);
      if (e.cape._task) { e.cape._task.fail(`${shortLabel(e.kind, e.value)} · ${st}`); e.cape._task = null; }
      toast(`CAPE ${st} for ${shortLabel(e.kind, e.value)}${j.detail ? ': ' + j.detail : ''}.`, true);
    }
    // else still running — leave as is
  }
}

function showCapeHits(srcEntity, ind) {
  const rows = [];
  (ind.domains || []).forEach(d => rows.push({ kind: 'domain', value: d, rel: 'cape:contacted_domain', display: d }));
  (ind.ips || []).forEach(p => rows.push({ kind: 'ip', value: p, rel: 'cape:contacted_ip', display: p }));
  (ind.urls || []).forEach(u => rows.push({ kind: 'url', value: u, rel: 'cape:contacted_url', display: u }));
  (ind.dropped || []).forEach(f => { if (f && f.sha256)
    rows.push({ kind: 'file', value: f.sha256, rel: 'cape:dropped', display: (f.name ? f.name + ' · ' : '') + f.sha256, label: f.name }); });

  if (!rows.length) { toast('CAPE report had no network/dropped IoCs to add.'); return; }

  const body = el('div');
  body.appendChild(el('div', { class: 'hint', style: 'margin-bottom:8px' },
    `CAPE detonation — ${rows.length} IoC(s). Tick rows, then Next to add them to the graph linked to “${shortLabel(srcEntity.kind, srcEntity.value)}”.`));
  const tbl = el('table', { class: 'hits' });
  tbl.appendChild(el('tr', {}, [
    el('th', { class: 'cb' }, el('input', { type: 'checkbox', onchange: ev =>
      $$('input.hit', tbl).forEach(c => c.checked = ev.target.checked) })),
    el('th', {}, 'type'), el('th', {}, 'indicator'), el('th', {}, 'relation')]));
  rows.forEach((r, i) => {
    const cb = el('input', { type: 'checkbox', class: 'hit' }); cb.checked = true; cb.dataset.i = i;
    tbl.appendChild(el('tr', {}, [
      el('td', { class: 'cb' }, cb),
      el('td', {}, r.kind),
      el('td', { class: 'mono' }, r.display),
      el('td', { class: 'hint' }, r.rel)]));
  });
  body.appendChild(tbl);

  openModal('cape · detonation', body, [
    { label: 'next → add selected', primary: true, onClick: () => {
        let added = 0;
        $$('input.hit:checked', tbl).forEach(c => {
          const r = rows[Number(c.dataset.i)];
          const ne = addEntity(r.kind, r.value, { silent: true });
          if (!ne) return;
          if (r.label && entName(ne) === ne.value) {
            ne.name = r.label;
            if (state.cy) state.cy.$id(ne.id).data('label', KIND[ne.kind].glyph + ' ' + entShort(ne));
          }
          addEdge(srcEntity.id, ne.id, r.rel); added++;
        });
        closeModal();
        if (added) { relayoutSoft(); toast(`added ${added} IoC(s) from CAPE`); }
      } },
    { label: 'cancel', onClick: () => closeModal() },
  ]);
}

/* ============================ add / import ============================== */
function doAdd() {
  const kind = $('#addType').value, v = $('#addValue').value.trim();
  if (!v) return;
  addEntity(kind, v); $('#addValue').value = ''; relayoutSoft();
}
function doBulk() {
  const lines = $('#bulkImport').value.split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
  let n = 0;
  lines.forEach(l => { const k = detectKind(l); if (k) { addEntity(k, l, { silent: true }); n++; } });
  $('#bulkImport').value = '';
  toast(`imported ${n} entit${n === 1 ? 'y' : 'ies'}`); relayoutSoft();
}
async function hashUploaded(file) {
  busy(true, 'hashing…');
  try {
    const buf = await file.arrayBuffer();
    const h = await sha256Hex(buf);
    const e = addEntity('file', h);
    if (e) { e.attributes['_local.filename'] = file.name; e.attributes['_local.size'] = file.size; }
    // Cache the bytes (IndexedDB, lightly obfuscated) so the file can be
    // statically analyzed or detonated later without re-uploading. For a large
    // file, first evict other cached samples to make room (the user explicitly
    // chose to upload it, so we honor it rather than refusing).
    if (file.size > 300 * 1024 * 1024 && file.size <= MAX_SAMPLE_BYTES) {
      const freed = await evictOtherSamples(h);
      if (freed) toast(`large upload — cleared ${freed} other cached sample(s) to free room`);
    }
    if (file.size <= MAX_SAMPLE_BYTES) {
      await putSample(h, file.name, buf);
    } else {
      toast(`file is ${(file.size/1048576).toFixed(0)} MB — over the ${MAX_SAMPLE_BYTES/1073741824} GB cache ceiling; added as hash only (you can still analyze it by re-uploading).`, true);
    }
    toast(`+ file ${h.slice(0, 12)}… (${file.name})`); relayoutSoft();
  } catch (e) { toast('hashing failed', true); }
  finally { busy(false); }
}

/* ===================== report upload (collapsible pane) ================
   PDF/DOCX reports are processed in a dedicated left PANE that is fully
   collapsed (zero width, hidden) until "upload report" opens it. The heavy
   extraction engine (report-engine.js) plus the CDN libraries it pulls (PDF.js
   / Mammoth / Tesseract) are injected ONLY when the pane opens and torn down
   when it closes — nothing here is in the base bundle, and if the CDNs are
   unreachable only report upload is affected. */
let _reportEngineScript = null;
let _reportPendingResult = null;

function openReportPane() {
  $('#middle').classList.add('report-open');
  // the graph column just got narrower — let Cytoscape recompute its viewport
  if (state.cy) setTimeout(() => { try { state.cy.resize(); } catch (e) {} }, 60);
}
function closeReportPane() {
  $('#middle').classList.remove('report-open');
  if (state.cy) setTimeout(() => { try { state.cy.resize(); state.cy.fit(undefined, 50); } catch (e) {} }, 60);
  // tear the engine + its CDN libraries out of the page
  try { if (window.IoCHubReport && window.IoCHubReport.teardown) window.IoCHubReport.teardown(); } catch (e) {}
  if (_reportEngineScript) { try { _reportEngineScript.remove(); } catch (e) {} _reportEngineScript = null; }
  try { delete window.IoCHubReport; } catch (e) { window.IoCHubReport = undefined; }
  _reportPendingResult = null;
  // reset pane UI
  $('#reportProg').style.width = '0';
  $('#reportLog').innerHTML = '';
  $('#reportCounts').innerHTML = '';
  $('#reportStatus').textContent = 'waiting…';
  $('#reportFname').textContent = '';
  $('#reportAdd').disabled = true;
}

// Inject report-engine.js once per open (it attaches window.IoCHubReport).
function loadReportEngine() {
  if (window.IoCHubReport) return Promise.resolve();
  return new Promise((res, rej) => {
    const s = document.createElement('script');
    s.src = new URL('report-engine.js', window.location.href).href;
    s.onload = () => res();
    s.onerror = () => rej(new Error('could not load report engine (report-engine.js)'));
    document.head.appendChild(s);
    _reportEngineScript = s;
  });
}

function uploadReport(file) {
  const lower = (file.name || '').toLowerCase();
  if (!lower.endsWith('.pdf') && !lower.endsWith('.docx')) {
    toast('report upload accepts .pdf or .docx only', true); return;
  }
  openReportPane();
  const logEl = $('#reportLog'), statusEl = $('#reportStatus'), progEl = $('#reportProg'),
        countsEl = $('#reportCounts'), addBtn = $('#reportAdd'), fnameEl = $('#reportFname');
  fnameEl.textContent = file.name;
  logEl.innerHTML = ''; countsEl.innerHTML = ''; addBtn.disabled = true; progEl.style.width = '0';
  statusEl.textContent = 'loading extractor…';

  const H = {
    log: (m, cls) => { const d = el('div', cls ? { class: cls } : {}, m); logEl.appendChild(d); logEl.scrollTop = logEl.scrollHeight; },
    status: (m) => { statusEl.textContent = m; },
    prog: (p) => { progEl.style.width = Math.max(0, Math.min(100, p)) + '%'; },
    counts: (io, hints, basis) => {
      countsEl.innerHTML = '';
      const mk = (label, n) => { const c = el('span', { class: 'chip' }); c.innerHTML = `${label}: <b>${n}</b>`; countsEl.appendChild(c); };
      mk('hashes', io.hashes.length); mk('ips', io.ips.length); mk('domains', io.domains.length); mk('urls', io.urls.length);
      mk('signers', hints.signers.length); mk('ASNs', hints.asns.length); mk('registrars', hints.registrars.length);
      countsEl.appendChild(el('span', { class: 'chip' }, basis));
    },
  };

  loadReportEngine()
    .then(() => window.IoCHubReport.run(file, H))
    .then(result => {
      _reportPendingResult = result;
      const total = result.hashes.length + result.ips.length + result.domains.length + result.urls.length
        + result.signers.length + result.asns.length + result.registrars.length;
      H.status(`done — ${total} item(s). Review, then add to the graph.`);
      H.log('extraction complete (' + result.basis + ').', 'ok');
      addBtn.disabled = total === 0;
      if (total === 0) H.log('nothing extractable found in this report.', 'err');
    })
    .catch(err => {
      H.status('extraction failed: ' + err.message);
      H.log(err.stack || String(err), 'err');
      H.log('If this is a network/CDN issue, the rest of IoCHub is unaffected — only report upload needs internet for its libraries.', '');
    });
}

// Build a report sub-entity and attach everything the extractor found.
function ingestReportResult(d) {
  const reportLabel = (d.reportName || 'report').slice(0, 60);
  const subField = 'report';
  const sid = subId(subField, reportLabel);
  if (!state.G.subs[sid]) { state.G.subs[sid] = { id: sid, field: subField, value: reportLabel, collapsed: false, attrs: [] }; cyAddSub(state.G.subs[sid]); }
  const rep = state.G.subs[sid];
  rep.attrs = rep.attrs || [];

  let created = 0, linked = 0;
  const link = (kind, value) => {
    const existed = !!state.G.entities[entityKey(kind, value)];
    const e = addEntity(kind, value, { silent: true });
    if (!e) return;
    addEdge(sid, e.id, 'from report', 'rel');
    existed ? linked++ : created++;
  };
  (d.hashes || []).forEach(v => link('file', v));
  (d.ips || []).forEach(v => link('ip', v));
  (d.domains || []).forEach(v => link('domain', v));
  (d.urls || []).forEach(v => link('url', v));

  const addHintSub = (field, value) => {
    const hid = subId(field, value);
    if (!state.G.subs[hid]) { state.G.subs[hid] = { id: hid, field, value: String(value), collapsed: false, attrs: [] }; cyAddSub(state.G.subs[hid]); }
    addEdge(sid, hid, field, 'sub');
  };
  (d.signers || []).forEach(v => addHintSub('signer', v));
  (d.asns || []).forEach(v => addHintSub('asn', v));
  (d.registrars || []).forEach(v => addHintSub('registrar', v));

  rep.attrs.push({ k: 'extracted_via', v: d.basis || 'text' });
  rep.attrs.push({ k: 'indicators', v: String((d.hashes||[]).length + (d.ips||[]).length + (d.domains||[]).length + (d.urls||[]).length) });

  saveDirty(); relayout();
  const total = created + linked;
  const hints = (d.signers||[]).length + (d.asns||[]).length + (d.registrars||[]).length;
  toast(`report "${reportLabel}": ${created} new, ${linked} linked${hints ? `, ${hints} hint sub-entit${hints===1?'y':'ies'}` : ''} (${d.basis||'text'})`);
}

/* ============================ theme / accent ============================ */
function applyTheme() {
  document.documentElement.classList.toggle('theme-night', state.settings.theme === 'night');
  document.documentElement.classList.toggle('theme-day', state.settings.theme === 'day');
  document.documentElement.style.setProperty('--accent', state.settings.accent);
  $('#btnTheme').textContent = state.settings.theme;
  $('#accent').value = state.settings.accent;
  if (state.cy) { state.cy.style(buildCyStyle()).update(); }
}

/* ============================ sub-field toggles ========================= */
function renderSubToggles() {
  const wrap = $('#subToggles'); wrap.innerHTML = '';
  DEFAULT_SUB_FIELDS.forEach(f => {
    const on = state.settings.subFields.includes(f);
    wrap.appendChild(el('span', { class: 'chip' + (on ? ' on' : ''),
      onclick: () => {
        const i = state.settings.subFields.indexOf(f);
        if (i >= 0) state.settings.subFields.splice(i, 1); else state.settings.subFields.push(f);
        saveSettings(); renderSubToggles();
      } }, f));
  });
}

// Render the autopivot configuration UI: depth, and per-type sensitivity +
// editable attribute rules. Each rule is a row of parts (attribute + facet +
// regex with a capturing group); a "+ group" button adds another part to the
// same rule (AND-combined into one query), and "+ rule" adds a new rule.
function renderAutopivotConfig() {
  const ap = state.settings.autopivot;
  const depthInput = $('#apDepth'); if (depthInput) depthInput.value = ap.depth;
  const root = $('#autopivotConfig'); if (!root) return;
  root.innerHTML = '';
  const ORDER = ['file', 'domain', 'ip', 'url'];
  // facet hint per type so the user knows what's queryable
  const facetHint = kind => Object.keys(VT_FACETS[kind] || {}).join(', ') || '—';

  ORDER.forEach(kind => {
    const cfg = ap.types[kind]; if (!cfg) return;
    const block = el('div', { class: 'ap-type' });
    block.append(el('div', { class: 'ap-type-head' }, [
      el('span', { class: 'ap-kind' }, kind),
      el('span', { class: 'ap-sens' }, [
        document.createTextNode('false-positive sensitivity '),
        (() => { const i = el('input', { type: 'number', min: '0', max: '100000', value: String(cfg.sensitivity) });
          i.style.width = '70px';
          i.addEventListener('change', () => { cfg.sensitivity = Math.max(0, parseInt(i.value || '30', 10)); saveSettings(); });
          return i; })(),
        el('span', { class: 'hint' }, ' max hits to still add'),
      ]),
    ]));

    const rulesWrap = el('div', { class: 'ap-rules' });
    function drawRules() {
      rulesWrap.innerHTML = '';
      (cfg.rules || []).forEach((rule, ri) => {
        const card = el('div', { class: 'ap-rule' });
        // header: enable + name + delete
        const en = el('input', { type: 'checkbox' }); en.checked = !!rule.enabled;
        en.addEventListener('change', () => { rule.enabled = en.checked; saveSettings(); });
        const nm = el('input', { type: 'text', value: rule.name || '', placeholder: 'rule name' });
        nm.style.flex = '1';
        nm.addEventListener('change', () => { rule.name = nm.value; saveSettings(); });
        const del = el('button', { class: 'danger', title: 'delete rule',
          onclick: () => { cfg.rules.splice(ri, 1); saveSettings(); drawRules(); } }, '✕');
        card.append(el('div', { class: 'ap-rule-head' }, [
          el('label', { class: 'lbl' }, [en, document.createTextNode(' enabled')]), nm, del ]));

        // parts (attribute + facet + regex)
        (rule.parts || []).forEach((p, pi) => {
          const row = el('div', { class: 'ap-part' });
          const attr = el('input', { type: 'text', value: p.attr || '', placeholder: 'attribute path (e.g. whois)' });
          attr.addEventListener('change', () => { p.attr = attr.value.trim(); saveSettings(); });
          const facet = el('input', { type: 'text', value: p.facet || '', placeholder: 'facet (e.g. registrar)' });
          facet.style.width = '120px';
          facet.addEventListener('change', () => { p.facet = facet.value.trim(); saveSettings(); });
          const rx = el('input', { type: 'text', value: p.regex || '', placeholder: 'regex with (capturing group)' });
          rx.style.flex = '1'; rx.style.fontFamily = 'monospace';
          rx.addEventListener('change', () => { p.regex = rx.value; saveSettings(); });
          const rm = el('button', { title: 'remove this attribute from the rule',
            onclick: () => { rule.parts.splice(pi, 1); saveSettings(); drawRules(); } }, '−');
          row.append(attr, facet, rx, rm);
          card.append(row);
        });
        // + group (adds another attribute/capturing-group part to this rule)
        card.append(el('button', { class: 'ap-add',
          onclick: () => { rule.parts = rule.parts || []; rule.parts.push({ attr: '', facet: '', regex: '(.+)' }); saveSettings(); drawRules(); } },
          '+ group (another attribute)'));
        rulesWrap.append(card);
      });
      rulesWrap.append(el('button', { class: 'ap-add primary',
        onclick: () => { cfg.rules = cfg.rules || []; cfg.rules.push({ enabled: true, name: 'new rule', parts: [{ attr: '', facet: '', regex: '(.+)' }] }); saveSettings(); drawRules(); } },
        '+ rule'));
    }
    drawRules();
    block.append(rulesWrap);
    block.append(el('div', { class: 'hint', style: 'margin-top:4px' }, `queryable facets for ${kind}: ${facetHint(kind)}`));
    root.append(block);
  });
}

/* ============================ auth / backend ============================ */
function authModal(opts) {
  opts = opts || {};
  const reauth = !!opts.reauth;   // re-auth mid-session: keep the current graph
  if (state.token && !reauth) return sessionModal();   // already logged in -> session panel
  const body = el('div');
  body.appendChild(el('div', { class: 'hint', style: 'margin-bottom:10px' },
    reauth
      ? 'Your session dropped (inactivity, or your source IP changed via the proxy). Re-enter your password to reconnect — your current graph is kept; nothing is lost.'
      : 'Log in. Your password is never sent to the server — it stays in this browser and ' +
        'decrypts your graphs and VirusTotal key locally. Accounts are created by the admin.'));
  const url = el('input', { type: 'text', value: state.settings.backendUrl, placeholder: 'backend url (blank = same origin)' });
  const u = el('input', { type: 'text', placeholder: 'username', autocomplete: 'username', value: reauth ? (state.user || sessionStorage.getItem('iochub.user') || '') : '' });
  const p = el('input', { type: 'password', placeholder: 'password', autocomplete: 'current-password' });
  const mk = (lbl, node) => el('div', { class: 'field-row' }, [el('label', {}, lbl), node]);
  body.append(mk('backend url', url), mk('username', u), mk('password', p));
  const status = el('div', { class: 'hint' });
  body.append(status);

  async function doLogin() {
    state.settings.backendUrl = url.value.trim(); saveSettings(); syncTopState();
    const username = u.value.trim(), password = p.value;
    if (!username || !password) { status.textContent = 'username and password required'; return; }
    try {
      status.innerHTML = '<span class="spin"></span> deriving key & logging in…';
      const secret = await deriveAuthSecret(password, username);
      const r = await fetch(backendBase() + '/api/auth/login', { method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, secret }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.token) { status.innerHTML = `<span style="color:var(--danger)">${esc(j.error || ('HTTP ' + r.status))}</span>`; return; }
      // Derive the (separate) content key and hold it in memory only.
      state.token = j.token; state.user = username; state.isAdmin = !!j.is_admin;
      state.authSource = 'local'; state.serverSideEnc = false;
      state.encKey = await deriveEncKey(password, username);
      sessionStorage.setItem('iochub.token', j.token);
      sessionStorage.setItem('iochub.user', username);
      sessionStorage.setItem('iochub.admin', j.is_admin ? '1' : '');
      if (reauth) {
        // Reconnect only: keep the live graph, just refresh the VT key + state.
        try { const env = await apiCall('/api/vtkey'); const obj = await decryptObj(env); state.vtKey = (obj && obj.key) ? obj.key : state.vtKey; } catch (e) {}
        try { const env = await apiCall('/api/mispkey'); const obj = await decryptObj(env); state.mispKey = (obj && obj.key) ? obj.key : state.mispKey; } catch (e) {}
        syncTopState();
        toast('reconnected as ' + username);
      } else {
        await afterLogin();
        toast('logged in as ' + username + (j.is_admin ? ' (admin)' : ''));
      }
      backendAlive(true);
      startKeepAlive();
      closeModal();
    } catch (e) { status.innerHTML = `<span style="color:var(--danger)">${esc(e.message || 'login failed')}</span>`; }
  }
  // --- Entra ID SSO (single tenant). Skeleton: the live OAuth redirect is not
  // wired yet, so this calls the backend SSO endpoint which is disabled by
  // default (returns a clear message). Once the OAuth flow exists, this is
  // where the obtained id_token would be exchanged. SSO accounts are encrypted
  // server-side by default; users can add a passphrase afterwards.
  async function doSso() {
    state.settings.backendUrl = url.value.trim(); saveSettings();
    status.innerHTML = '<span class="spin"></span> contacting Entra SSO…';
    try {
      // No live token yet — send an empty token so the backend reports its
      // skeleton/disabled status cleanly. (Real flow: obtain id_token via MSAL.)
      const r = await fetch(backendBase() + '/api/auth/sso', { method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id_token: window.__entra_id_token || '' }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.token) {
        status.innerHTML = `<span style="color:var(--danger)">${esc(j.error || ('SSO unavailable (HTTP ' + r.status + ')'))}</span>`;
        return;
      }
      // Server-side-encrypted SSO session: the backend holds the content key, so
      // the browser doesn't derive one. Graphs are returned already-decryptable
      // by the relay; we keep encKey null and rely on the server key until/unless
      // the user adds a passphrase.
      state.token = j.token; state.user = j.username; state.isAdmin = !!j.is_admin;
      state.authSource = 'entra'; state.serverSideEnc = true; state.encKey = null;
      sessionStorage.setItem('iochub.token', j.token);
      sessionStorage.setItem('iochub.user', j.username);
      sessionStorage.setItem('iochub.admin', j.is_admin ? '1' : '');
      await afterLogin();
      backendAlive(true); startKeepAlive(); closeModal();
      toast('signed in via Entra SSO as ' + j.username);
    } catch (e) { status.innerHTML = `<span style="color:var(--danger)">${esc(e.message || 'SSO failed')}</span>`; }
  }

  openModal('log in', body, [
    { label: 'log in', primary: true, onClick: doLogin },
    { label: 'sign in with Entra ID (SSO)', onClick: doSso },
    { label: 'close', onClick: closeModal },
  ]);
  setTimeout(() => u.focus(), 30);
}

// After a successful login: pull and decrypt the stored VT key, refresh slots.
async function afterLogin() {
  syncTopState();
  try {
    const env = await apiCall('/api/vtkey');
    const obj = await decryptObj(env);
    state.vtKey = (obj && obj.key) ? obj.key : '';
  } catch (e) { state.vtKey = ''; }      // wrong key or none yet
  try {
    const env = await apiCall('/api/mispkey');
    const obj = await decryptObj(env);
    state.mispKey = (obj && obj.key) ? obj.key : '';
  } catch (e) { state.mispKey = ''; }
  syncTopState();
  await refreshSlots();
}

// Session panel for a logged-in user: identity, change password, admin tools, logout.
function sessionModal() {
  const sso = state.authSource === 'entra';
  const body = el('div');
  body.append(el('div', { class: 'field-row' }, [el('label', {}, 'signed in'),
    el('div', {}, state.user + (state.isAdmin ? '  · admin' : '') + (sso ? '  · SSO (Entra)' : ''))]));
  if (sso && state.serverSideEnc) {
    // Option A: server holds the key. Be explicit about the tradeoff.
    body.append(el('div', { class: 'warn-box', style: 'margin:6px 0' },
      '⚠ SSO account: your graphs are encrypted with a key held on the server, so the server — and your Entra/host directory admins — can read them. Set a graph passphrase to switch to browser-only (zero-knowledge) encryption that the server cannot read.'));
  } else if (sso) {
    body.append(el('div', { class: 'hint', style: 'margin:6px 0' },
      'SSO account with a graph passphrase set — content is encrypted in this browser; the server cannot read it.'));
  } else {
    body.append(el('div', { class: 'hint', style: 'margin:6px 0' },
      'Your content is encrypted in this browser with your password. Logging out clears the in-memory key.'));
  }

  const acts = [];
  if (sso && state.serverSideEnc) acts.push({ label: 'add graph passphrase', onClick: () => { closeModal(); setPassphraseModal(); } });
  if (!sso) acts.push({ label: 'change password', onClick: () => { closeModal(); changePasswordModal(); } });
  if (state.isAdmin) acts.push({ label: 'create user', onClick: () => { closeModal(); adminCreateUserModal(); } });
  if (state.isAdmin) acts.push({ label: 'query log', onClick: () => { closeModal(); adminQueryLogModal(); } });
  acts.push({ label: 'log out', onClick: () => { closeModal(); logout(); } });
  acts.push({ label: 'close', onClick: closeModal });
  openModal('session', body, acts);
}

// Admin: view the persisted log of analyst-edited VT queries (newest first).
async function adminQueryLogModal() {
  const body = el('div');
  body.append(el('div', { class: 'hint', style: 'margin-bottom:8px' },
    'VT queries analysts hand-edited away from the auto-built query (server-side, all users). Useful for spotting better facet mappings.'));
  const list = el('div', { style: 'max-height:50vh; overflow:auto' });
  body.append(list);
  list.append(el('div', { class: 'hint' }, 'loading…'));
  openModal('query log', body, [{ label: 'close', onClick: closeModal }]);
  try {
    const r = await apiCall('/api/admin/query_log');
    const entries = (r && r.entries) || [];
    list.innerHTML = '';
    if (!entries.length) { list.append(el('div', { class: 'hint' }, 'no edited queries logged yet')); return; }
    entries.forEach(e => {
      const card = el('div', { class: 'ql-entry' });
      card.append(el('div', { class: 'ql-meta' },
        `${new Date(e.ts).toLocaleString()} · ${e.username}`));
      card.append(el('div', { class: 'ql-final mono' }, e.final));
      if (e.attributes && e.attributes.length)
        card.append(el('div', { class: 'ql-attrs hint' }, 'from: ' + e.attributes.join(', ')));
      if (e.auto && e.auto !== e.final)
        card.append(el('div', { class: 'ql-auto hint mono' }, 'auto was: ' + e.auto));
      list.append(card);
    });
  } catch (err) {
    list.innerHTML = ''; list.append(el('div', { class: 'hint' }, 'could not load: ' + err.message));
  }
}

// SSO users: set a graph passphrase to upgrade option A → B (zero-knowledge).
// We derive both the auth secret and the content key from the new passphrase,
// re-encrypt the current graphs + VT key under the new content key, and send
// them with the new auth secret. After this the server can't read the content.
function setPassphraseModal() {
  const body = el('div');
  body.append(el('div', { class: 'hint', style: 'margin-bottom:10px' },
    'Set a graph passphrase. Your graphs will be re-encrypted in this browser under a key derived from it; the server keeps only a verifier and can no longer read your content. You will enter this passphrase each session (in addition to SSO).'));
  const p1 = el('input', { type: 'password', placeholder: 'new graph passphrase', autocomplete: 'new-password' });
  const p2 = el('input', { type: 'password', placeholder: 'confirm passphrase', autocomplete: 'new-password' });
  const mk = (l, n) => el('div', { class: 'field-row' }, [el('label', {}, l), n]);
  body.append(mk('passphrase', p1), mk('confirm', p2));
  const status = el('div', { class: 'hint' }); body.append(status);
  openModal('add graph passphrase', body, [
    { label: 'set passphrase', primary: true, onClick: async () => {
        if (p1.value.length < 10) { status.textContent = 'use at least 10 characters'; return; }
        if (p1.value !== p2.value) { status.textContent = 'passphrases do not match'; return; }
        status.textContent = 'encrypting…';
        try {
          const username = state.user;
          const newSecret = await deriveAuthSecret(p1.value, username);
          const newKey = await deriveEncKey(p1.value, username);
          // re-encrypt current graphs (both manual slots + autosave) and VT key
          const graphs = {};
          for (const n of [1, 2, AUTOSAVE_SLOT]) {
            try {
              const env = await apiCall('/api/graphs/' + n);
              const g = await decryptObj(env);          // currently decryptable (server-key era we held plaintext in memory)
              if (g) graphs[n] = await encryptObj(g, newKey);
            } catch (e) {/* slot empty or unreadable; skip */}
          }
          let vt = null;
          if (state.vtKey) vt = await encryptObj({ key: state.vtKey }, newKey);
          await apiCall('/api/auth/set_passphrase', { method: 'POST',
            body: { new_secret: newSecret, graphs, vt } });
          state.encKey = newKey; state.serverSideEnc = false;
          closeModal();
          toast('graph passphrase set — your content is now browser-only encrypted');
        } catch (err) { status.textContent = 'failed: ' + err.message; }
      } },
    { label: 'cancel', onClick: closeModal },
  ]);
}

async function logout() {
  stopKeepAlive();
  try { await fetch(backendBase() + '/api/auth/logout', { method: 'POST', headers: authHeader() }); } catch (e) {}
  // Re-encrypt-on-logout is implicit: content is only ever stored encrypted, and
  // the in-memory key is dropped here so nothing readable remains in the tab.
  state.token = ''; state.user = ''; state.isAdmin = false; state.encKey = null; state.vtKey = ''; state.authSource = 'local'; state.serverSideEnc = false;
  state.slotMeta = {}; state.activeSlot = null;
  sessionStorage.removeItem('iochub.token'); sessionStorage.removeItem('iochub.user'); sessionStorage.removeItem('iochub.admin');
  newGraph(); syncTopState(); renderSlots();
  toast('logged out — session key cleared');
}

// Change the caller's password. We re-encrypt the VT key and both graph slots
// under the new key and send them with the new auth secret, so the server swap
// is atomic and nothing is left under the old key.
function changePasswordModal() {
  const body = el('div');
  const cur = el('input', { type: 'password', placeholder: 'current password', autocomplete: 'current-password' });
  const nw = el('input', { type: 'password', placeholder: 'new password (min 8)', autocomplete: 'new-password' });
  const nw2 = el('input', { type: 'password', placeholder: 'repeat new password', autocomplete: 'new-password' });
  const mk = (lbl, node) => el('div', { class: 'field-row' }, [el('label', {}, lbl), node]);
  body.append(mk('current', cur), mk('new', nw), mk('repeat', nw2));
  const status = el('div', { class: 'hint' });
  body.append(status);

  async function submit() {
    const c = cur.value, n = nw.value;
    if (n.length < 8) { status.textContent = 'new password must be at least 8 characters'; return; }
    if (n !== nw2.value) { status.textContent = 'new passwords do not match'; return; }
    try {
      status.innerHTML = '<span class="spin"></span> re-encrypting your content…';
      const oldSecret = await deriveAuthSecret(c, state.user);
      const newSecret = await deriveAuthSecret(n, state.user);
      const newKey = await deriveEncKey(n, state.user);
      // Re-encrypt whatever is stored, decrypting with the current key.
      const payload = { old_secret: oldSecret, new_secret: newSecret, graphs: {}, vt: null };
      for (const slot of [1, 2]) {
        try {
          const env = await apiCall('/api/graphs/' + slot);
          const g = await decryptObj(env);
          if (g) payload.graphs[slot] = await encryptObj(g, newKey);
        } catch (e) {}
      }
      if (state.vtKey) payload.vt = await encryptObj({ key: state.vtKey }, newKey);
      const r = await apiCall('/api/auth/change_password', { method: 'POST', body: payload });
      if (r.ok) {
        state.encKey = newKey;            // adopt the new session key
        toast('password changed; content re-encrypted'); closeModal();
      }
    } catch (e) { status.innerHTML = `<span style="color:var(--danger)">${esc(e.message || 'change failed')}</span>`; }
  }
  openModal('change password', body, [
    { label: 'change password', primary: true, onClick: submit },
    { label: 'cancel', onClick: closeModal },
  ]);
}

// Admin-only: create a new account. The admin types the new user's initial
// password; we derive that user's auth secret in the browser and send only it.
function adminCreateUserModal() {
  const body = el('div');
  body.appendChild(el('div', { class: 'hint', style: 'margin-bottom:8px' },
    'Create an account. Give the user this username and initial password; they should ' +
    'change the password after first login. The password is turned into a verifier here — ' +
    'the server never receives it.'));
  const u = el('input', { type: 'text', placeholder: 'new username (3–64: letters, digits, - _ .)' });
  const p = el('input', { type: 'password', placeholder: 'initial password (min 8)', autocomplete: 'new-password' });
  const mk = (lbl, node) => el('div', { class: 'field-row' }, [el('label', {}, lbl), node]);
  body.append(mk('username', u), mk('password', p));
  const status = el('div', { class: 'hint' });
  body.append(status);

  async function submit() {
    const username = u.value.trim(), password = p.value;
    if (!username || password.length < 8) { status.textContent = 'username and an 8+ char password required'; return; }
    try {
      status.innerHTML = '<span class="spin"></span> creating…';
      const secret = await deriveAuthSecret(password, username);
      const r = await apiCall('/api/admin/create_user', { method: 'POST', body: { username, secret } });
      if (r.ok) { toast('created user ' + username); closeModal(); }
    } catch (e) { status.innerHTML = `<span style="color:var(--danger)">${esc(e.message || 'create failed')}</span>`; }
  }
  openModal('create user (admin)', body, [
    { label: 'create user', primary: true, onClick: submit },
    { label: 'cancel', onClick: closeModal },
  ]);
}

async function pingBackend() {
  try {
    const r = await fetch(backendBase() + '/healthz');
    toast(r.ok ? 'backend ok' : 'backend HTTP ' + r.status, !r.ok);
  } catch (e) { toast('backend unreachable', true); }
}
// ---- backend keep-alive ----
// Over proxies like Zscaler an idle session is torn down, and the client source
// IP can change (which invalidates an IP-bound token). We poll the backend
// every few seconds; on failure we flag the backend indicator and let the user
// click it to re-authenticate WITHOUT a page reload, so the in-memory graph and
// any unsaved work survive.
state.backendOk = true;
function backendAlive(ok) {
  state.backendOk = ok;
  const el_ = $('#authState'); if (!el_) return;
  if (!state.token) return;                 // logged-out state handled by syncTopState
  if (ok) {
    el_.textContent = (state.user || 'online') + (state.isAdmin ? ' ·admin' : '');
    el_.className = 'ok'; el_.title = ''; el_.style.cursor = '';
  } else {
    el_.textContent = '⚠ reconnect';
    el_.className = 'bad'; el_.title = 'Backend unreachable or session expired — click to reconnect'; el_.style.cursor = 'pointer';
  }
}
let _keepAliveTimer = null;
function startKeepAlive() {
  if (_keepAliveTimer) return;
  _keepAliveTimer = setInterval(checkBackend, 5000);
}
function stopKeepAlive() { if (_keepAliveTimer) { clearInterval(_keepAliveTimer); _keepAliveTimer = null; } }
async function checkBackend() {
  if (!state.token) return;
  try {
    // /api/me is auth + IP bound, so it catches both a dead backend AND an
    // IP/token change (401) — exactly the Zscaler failure modes.
    const r = await fetch(backendBase() + '/api/me', { headers: authHeader(), cache: 'no-store' });
    if (r.ok) { if (!state.backendOk) backendAlive(true); return; }
    if (r.status === 401) {
      // session/IP invalidated — drop the dead token but KEEP the graph + keys
      state.token = ''; sessionStorage.removeItem('iochub.token');
      backendAlive(false);
      toast('Backend session expired (inactivity or IP change) — click “reconnect”.', true);
    } else {
      backendAlive(false);
    }
  } catch (e) {
    backendAlive(false);
  }
}

// Build a masked representation of an API key like  8\w{62}a  (first char,
// a regex-style run of the middle length, last char) so it's clear a key is
// saved without revealing it.
function maskKey(k) {
  if (!k) return '';
  if (k.length <= 2) return k[0] + '…';
  return `${k[0]}\\w{${k.length - 2}}${k[k.length - 1]}`;
}
function syncTopState() {
  const masked = maskKey(state.vtKey);
  $('#keyState').textContent = state.vtKey ? masked : 'not set';
  $('#keyState').className = state.vtKey ? 'ok mono' : 'bad';
  if (state.vtKey) $('#keyState').title = 'a VirusTotal key is saved (shown masked)';
  // Reflect the saved key in the input's placeholder so the settings field also
  // shows one is stored, without exposing it.
  const vk = $('#vtKey');
  if (vk) vk.placeholder = state.vtKey ? masked + '  (saved — type to replace)' : 'paste VT v3 api key';
  $('#authState').textContent = state.token ? (state.user || 'online') + (state.isAdmin ? ' ·admin' : '') : 'offline';
  $('#authState').className = state.token ? 'ok' : 'bad';
  $('#backendUrl').value = state.settings.backendUrl;
  // MISP fields
  const mk = $('#mispKey');
  if (mk) mk.placeholder = state.mispKey ? maskKey(state.mispKey) + '  (saved — type to replace)' : 'paste MISP automation api key';
  const mu = $('#mispUrl'); if (mu && document.activeElement !== mu) mu.value = state.settings.mispUrl || '';
  const ma = $('#mispAutoEnrich'); if (ma) ma.checked = !!state.settings.mispAutoEnrich;
  const b = $('#btnAuth'); if (b) b.textContent = state.token ? 'session' : 'connect…';
}

/* ============================ wiring / init ============================= */
function wire() {
  $('#btnSettings').addEventListener('click', () => $('#settingsPanel').classList.toggle('open'));
  $('#btnTheme').addEventListener('click', () => {
    state.settings.theme = state.settings.theme === 'night' ? 'day' : 'night';
    saveSettings(); applyTheme();
  });
  $('#accent').addEventListener('input', e => { state.settings.accent = e.target.value; saveSettings(); applyTheme(); });

  $('#btnSaveKey').addEventListener('click', async () => {
    if (!loggedIn()) { toast('Log in first — the key is stored encrypted on the server.', true); return; }
    state.vtKey = $('#vtKey').value.trim();
    try {
      if (state.vtKey) { await apiCall('/api/vtkey', { method: 'PUT', body: await encryptObj({ key: state.vtKey }) }); }
      else { await apiCall('/api/vtkey', { method: 'DELETE' }); }
      syncTopState();
      toast(state.vtKey ? 'VT key encrypted & saved to your account' : 'VT key cleared');
    } catch (e) { toast('could not save key: ' + e.message, true); }
  });
  $('#btnClearKey').addEventListener('click', async () => {
    state.vtKey = ''; $('#vtKey').value = '';
    try { if (loggedIn()) await apiCall('/api/vtkey', { method: 'DELETE' }); } catch (e) {}
    syncTopState(); toast('VT key cleared');
  });
  // MISP key (encrypted on the backend like the VT key), instance URL, toggle
  $('#btnSaveMisp').addEventListener('click', async () => {
    if (!loggedIn()) { toast('Log in first — the MISP key is stored encrypted on the server.', true); return; }
    state.mispKey = $('#mispKey').value.trim();
    try {
      if (state.mispKey) { await apiCall('/api/mispkey', { method: 'PUT', body: await encryptObj({ key: state.mispKey }) }); }
      else { await apiCall('/api/mispkey', { method: 'DELETE' }); }
      syncTopState();
      toast(state.mispKey ? 'MISP key encrypted & saved to your account' : 'MISP key cleared');
    } catch (e) { toast('could not save MISP key: ' + e.message, true); }
  });
  $('#btnClearMisp').addEventListener('click', async () => {
    state.mispKey = ''; $('#mispKey').value = '';
    try { if (loggedIn()) await apiCall('/api/mispkey', { method: 'DELETE' }); } catch (e) {}
    syncTopState(); toast('MISP key cleared');
  });
  $('#mispUrl').addEventListener('change', e => { state.settings.mispUrl = e.target.value.trim(); saveSettings(); });
  $('#mispAutoEnrich').addEventListener('change', e => {
    state.settings.mispAutoEnrich = e.target.checked; saveSettings();
    if (e.target.checked && !mispConfigured()) toast('Set a MISP key and instance URL to use auto-enrich.', true);
    else if (e.target.checked) toast('MISP auto-enrich on — new entities will be queried automatically.');
  });
  $('#backendUrl').addEventListener('change', e => { state.settings.backendUrl = e.target.value.trim(); saveSettings(); });
  $('#btnPing').addEventListener('click', pingBackend);
  $('#showSubs').addEventListener('change', e => {
    state.settings.showSubs = e.target.checked; saveSettings();
    if (state.cy) state.cy.$('.sub').style('display', e.target.checked ? 'element' : 'none');
  });

  $('#btnAdd').addEventListener('click', doAdd);
  $('#addValue').addEventListener('keydown', e => { if (e.key === 'Enter') doAdd(); });
  $('#btnBulk').addEventListener('click', doBulk);
  $('#btnHashFile').addEventListener('click', () => $('#hashFile').click());
  $('#hashFile').addEventListener('change', e => { if (e.target.files[0]) hashUploaded(e.target.files[0]); e.target.value = ''; });
  $('#btnReportFile').addEventListener('click', () => $('#reportFile').click());
  $('#reportFile').addEventListener('change', e => { if (e.target.files[0]) uploadReport(e.target.files[0]); e.target.value = ''; });
  $('#reportAdd').addEventListener('click', () => { if (_reportPendingResult) { ingestReportResult(_reportPendingResult); } closeReportPane(); });
  $('#reportClose').addEventListener('click', closeReportPane);
  $('#collReport').addEventListener('click', closeReportPane);

  $('#btnExport').addEventListener('click', exportXlsx);
  $('#btnExportMisp').addEventListener('click', exportMisp);
  $('#btnNewGraph').addEventListener('click', newGraph);
  $('#btnAuth').addEventListener('click', authModal);
  // Clicking the backend status when it's down opens the re-auth dialog.
  $('#authState').addEventListener('click', () => { if (state.token && !state.backendOk) authModal({ reauth: true }); });
  $('#btnTasks').addEventListener('click', () => {
    const p = $('#tasksPanel'); p.classList.toggle('open');
    $('#settingsPanel').classList.remove('open');
    if (p.classList.contains('open')) renderTasks();
  });
  $('#btnCloseTasks').addEventListener('click', () => $('#tasksPanel').classList.remove('open'));
  $('#btnClearTasks').addEventListener('click', () => {
    state.tasks = state.tasks.filter(t => t.status === 'running'); renderTasks();
  });

  $('#btnSelectMode').addEventListener('click', toggleSelectMode);
  $('#btnFit').addEventListener('click', () => state.cy && state.cy.fit(undefined, 40));
  $('#btnRelayout').addEventListener('click', relayout);
  $('#btnAutoPivot').addEventListener('click', autoPivot);
  const apDepth = $('#apDepth');
  if (apDepth) apDepth.addEventListener('change', () => {
    state.settings.autopivot.depth = Math.max(1, Math.min(6, parseInt(apDepth.value || '2', 10)));
    saveSettings();
  });
  $('#closeDrawer').addEventListener('click', closeDrawer);
  // Right-click the details header to get the same quick action menu.
  $('#drawerHead').addEventListener('contextmenu', ev => {
    ev.preventDefault();
    if (state.multiMode && state.multiIds) multiContextMenu(state.multiIds, ev.clientX, ev.clientY);
    else if (state.drawerEntity && state.G.entities[state.drawerEntity]) entityContextMenu(state.G.entities[state.drawerEntity], ev.clientX, ev.clientY);
  });
  initDrawerResize();
  $('#modalX').addEventListener('click', closeModal);
  $('#overlay').addEventListener('click', e => { if (e.target.id === 'overlay') closeModal(); });

  // collapsible panes
  function collapse(paneSel, midClass) {
    const pane = $(paneSel);
    const toggle = () => { pane.classList.toggle('collapsed');
      $('#middle').classList.toggle(midClass, pane.classList.contains('collapsed')); };
    pane.querySelector('.titlebar button').addEventListener('click', e => { e.stopPropagation(); toggle(); });
    pane.addEventListener('click', () => { if (pane.classList.contains('collapsed')) toggle(); });
  }
  collapse('#paneStore', 'store-collapsed');
  collapse('#paneList', 'list-collapsed');

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') { closeModal(); closeDrawer(); }
  });
}

function init() {
  loadSettings();
  // A token may survive a reload, but the in-memory encryption key cannot, so a
  // refresh requires logging in again to read content. Clear any stale token so
  // the UI state is honest about needing the password.
  state.token = ''; state.user = ''; state.isAdmin = false; state.encKey = null;
  sessionStorage.removeItem('iochub.token');
  state.slotMeta = {};
  initCy();
  applyTheme();
  syncTopState();
  renderSubToggles();
  renderAutopivotConfig();
  renderSlots();
  renderEntityList();
  updateStatus();
  wire();
}
document.addEventListener('DOMContentLoaded', init);
