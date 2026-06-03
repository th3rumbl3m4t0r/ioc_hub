# IoCHub

A browser-first platform for connecting Indicators of Compromise (IoCs) into a
relationship graph — files → domains → hosting IPs → more domains → more files —
with VirusTotal and MISP enrichment, checkbox-driven pivoting, on-demand report
extraction, and XLSX / MISP export.

IoCHub is a single small Rust backend serving a static, dependency-vendored
frontend (Cytoscape graph). It is designed to be **simple and secure over
permanent**: minimal moving parts, a tiny attack surface, and a
zero-knowledge-by-default credential model.

> **License:** GPLv3-or-later. See [`LICENSE`](LICENSE) and
> [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md).

---

## Default admin login

On first start the backend seeds a single admin account:

- **username:** `vmarik`
- **password:** `IoChUb`  ← **placeholder default — change it immediately**

Either set `IOCHUB_ADMIN_PASSWORD` before the very first start so the default is
never used, or log in once and change the password via the change-password
panel. Open registration is disabled; the admin creates all other users.

---

## Quick deploy (fresh install, RHEL 9.8)

This package installs onto a **clean RHEL 9.8 host**. It is a fresh-install
script — it will refuse to run if it detects an existing IoCHub, so it can never
clobber existing accounts/graphs by surprise.

TLS is **not** self-signed: the host must already have a real certificate (e.g.
from certbot/Let's Encrypt). The Apache vhost points at the certbot layout.

```bash
tar xzf IOCHUb-git.tar.gz
cd iochub
sudo IOCHUB_SERVER_NAME=iochub.example.org ./deploy.sh
```

What the installer does:

- verifies no existing IoCHub is present, then installs `httpd`, `mod_ssl`,
  `curl`, `bind-utils`, `whois`, `nmap`
- creates an unprivileged `iochub` service account
- installs the backend + frontend under `/opt/iochub`
- starts the systemd service (backend listens on `127.0.0.1:8787`)
- installs Apache vhosts: `iochub.conf` (80->443 redirect) and
  `iochub-le-ssl.conf` (443 reverse-proxy + security headers) using your
  existing certificate
- opens firewalld 80/443 and sets the SELinux `httpd_can_network_connect`
  boolean

Useful env vars: `IOCHUB_SERVER_NAME` (required), `IOCHUB_CERT_DIR`
(default `/etc/letsencrypt/live/<ServerName>`), `IOCHUB_PREFIX`
(default `/opt/iochub`), `IOCHUB_ADMIN_PASSWORD`.

### Build from source

Backend (Rust, stable toolchain):

```bash
cd backend
cargo build --release      # -> target/release/iochub
```

The frontend is static; no build step. Serve `frontend/` behind the backend (or
let the backend serve it via `IOCHUB_PUBLIC`).

---

## Security model

- **Zero-knowledge credentials.** The browser derives two PBKDF2-HMAC-SHA256
  (210k iterations) values from your password: an *auth secret* (login
  credential, stored on the server only as an Argon2id hash) and an *AES-GCM
  content key* that **never leaves the browser**. Your graphs and your
  VirusTotal/MISP API keys are stored on the server only as AES-GCM ciphertext,
  decrypted in the browser. A page reload requires logging in again.
- **IP-bound sessions.** A session token is tied to the source IP; a request
  from a different IP is rejected.
- **Login throttle.** A permissive per-IP backstop against brute force: 150
  failed logins within an hour blocks that IP for 24 hours. (In-memory; resets
  on restart. Tune in `auth.rs` if needed.)
- **Admin-only account creation.** No open registration.
- **API keys never hit the server in clear.** The VirusTotal key travels
  per-request through a same-origin relay (VT has no CORS); the MISP key is used
  for direct browser->MISP queries (MISP supports CORS).

### Azure / Entra ID SSO — NOT finished (disabled by default)

The Entra ID single-sign-on path is an **unfinished skeleton** and is **disabled
by default**. It only runs if you set `IOCHUB_ENABLE_SSO=1`, and you should not
do that in production yet: the SSO endpoint currently decodes the Entra JWT to
read the tenant id but **does not verify the token signature** (or `aud`/`iss`/
`exp`) against the tenant's JWKS. Until that verification is implemented, an
attacker who can reach the server could forge a token, so SSO must stay off.
Local zero-knowledge accounts are the supported login method. The plumbing
(single-tenant restriction via `IOCHUB_ENTRA_TENANT`, optional passphrase
upgrade for SSO users) is in place for when the OAuth flow is completed.

---

## Features

### Graph & UI
- Cytoscape graph styled minimally (BlackArch/X11 feel); day/night toggle
  switches the graph background.
- Collapsible panes: graph storage (leftmost) and entity lists (left). Two
  user graph slots plus an autosave slot.
- **Layered selection highlight** - selecting an entity draws a faint halo on it,
  a fainter halo on its directly-connected entities/sub-entities, and lifts the
  connecting edge labels. Nothing is hidden or dimmed.
- **Task-running halo** - any entity with a task in flight (VT enrich, static,
  host analysis, CAPE, MISP) shows a faint halo tinted halfway between the accent
  and the background, so you can see what's working.
- **Clump layout** (re-layout button) - groups entities into clumps by topology
  (shared sub-entities) with attribute hierarchy as a tie-breaker, places each
  entity type in its own broad X-region, pulls connected clumps together, and
  drops sub-entities into the gaps. Adding entities otherwise drops them into
  open space (re-layout is the only thing that imposes clustering).
- **Right-click context menu** on any entity mirrors the details-pane actions
  (enrich, MISP, pivot, static/host/CAPE, XQL, VT link, download, autopivot from
  here, remove) plus per-relationship expand actions with in-graph/on-VT counts.

### Enrichment & pivoting
- **VirusTotal**: object enrichment fills VT-style attribute fields; relationship
  expansion (contacted_domains, embedded_urls, resolutions, ...) with an
  in-graph/on-VT count badge per relationship.
- **MISP**: query any entity against your MISP instance directly from the
  browser. Common attributes (hashes) merge under the same keys as VirusTotal so
  they cross-check and VT can overwrite them; tags/comments/categories become
  `misp.*` attributes; events and galaxies spawn as sub-entities. Optional
  **auto-enrich** queries every newly added entity automatically.
- **Checkbox pivoting**: select attributes (including combinations) in the
  details table, build a VT Intelligence search, review the hits (with an
  "in graph" badge and "select all" preselected), and add the chosen ones -
  adds link to existing entities rather than duplicating. Pivot sub-entities
  remember their query and offer a one-click **re-run pivot**.
- **Static analysis** (backend): hand-rolled PE parser + md5/sha1/sha256/ssdeep/
  imphash/authentihash and an Authenticode signer chain, for uploaded files.
- **Host analysis** (backend): domains via `dig`/`whois`/TLS cert (resolved IPs
  are added as direct `resolutions` edges, like a VT expand); IPs via `whois`
  plus an `nmap -Pn --script ssl-cert -p-` full-port scan (open ports, services,
  and the server certificate). Available per-entity and in bulk over a selection.
- **CAPE sandbox** (REST): IoCHub drives an **existing** CAPE instance you run
  yourself (configure `url`/`token` in `cape.conf`), gated by a per-user regex
  allow-list. CAPE is not installed or managed by IoCHub.
- **Autopivot**: expand the whole graph (or from a selected entity) using
  configurable per-type relationship/attribute rules with false-positive
  sensitivity gates.

### Report extraction (PDF/DOCX)
- An isolated **report extractor pane** opens on demand. It loads PDF.js,
  Mammoth, and Tesseract from a CDN **only when opened** and tears them down on
  close - none of that is in the base bundle, and if the CDN is unreachable only
  report upload is affected.
- Two passes: text extraction first, OCR only for pages without selectable text.
  Extracts hashes/IPs/domains/URLs (with defanging), and turns signer/ASN/
  registrar hints into sub-entities, all linked to a `report` sub-entity.

### Export
- **XLSX**: one sheet per entity type plus a relations sheet. Columns are ordered
  per type - files lead with hashes then `meaningful_name`; IPs with
  `as_owner`/`asn`/`whois`; domains with `registrar`/`whois` - followed by the
  attributes used for graph connections/pivots, then the rest. Unix timestamps
  render as ISO-8601.
- **MISP**: export a MISP event JSON - files become MISP `file` objects bundling
  hashes + filenames; domains/IPs/URLs become typed network attributes;
  restricted to meaningful indicators (like AnyRun's MISP export).
- A **date translation layer** renders bare Unix timestamps (seconds/ms/us) as
  ISO-8601 everywhere they appear.

### XSIAM / XQL
- Generate an XQL query for a Cortex XSIAM tenant from an entity and its checked
  attributes. **Bulk XQL** consolidates a multi-selection of files (or IPs/
  domains) into one query: equality becomes `in (...)` lists, "contains" becomes
  a regexp (`~=`) of pipe-joined values, file names/paths use
  `action_process_image_path`. Copy-only; no live connector runs it yet.

---

## Configuration

| Env var | Purpose | Default |
|---|---|---|
| `IOCHUB_ADDR` | backend bind address | `127.0.0.1:8787` |
| `IOCHUB_DATA` | data dir (accounts, graphs, keys) | `./data` |
| `IOCHUB_PUBLIC` | static frontend dir | `./public` |
| `IOCHUB_ADMIN_PASSWORD` | seed admin password (first start only) | `IoChUb` |
| `IOCHUB_THREADS` | worker threads | `8` |
| `IOCHUB_ENABLE_SSO` | enable Entra ID SSO endpoint (skeleton — leave off) | off |
| `IOCHUB_ENTRA_TENANT` | Entra tenant id override | placeholder |

**MISP** instance URL + API key are set in Settings. Because MISP queries run
directly from the browser, you must add your MISP origin to the `connect-src` in
`/etc/httpd/conf.d/iochub-le-ssl.conf` and reload httpd (no MISP host is allowed
by default).

**CAPE** is configured in `<data>/cape.conf` (`enabled`, `url`, `token`,
`insecure`, and an `[allow]` regex). Set the CAPE side's `ratelimit=no` for
polling to work.

---

## Repository layout

```
backend/        Rust backend (single binary)
  src/          main, auth, store, vt, cape, static_engine, host_analysis, http_util
frontend/       static app
  index.html, app.css, app.js, report-engine.js
  vendor/       cytoscape.min.js, xlsx.full.min.js  (vendored, air-gapped)
deploy/         deploy.sh (fresh-install RHEL 9.8), vhosts, systemd unit
LICENSE                     GPLv3
THIRD-PARTY-LICENSES.md     dependency attributions
```

---

## Caveats

- **Azure/Entra SSO is unfinished** and disabled by default — see the security
  section. Do not enable it in production until token-signature verification is
  implemented.
- The report extractor's OCR and the MISP query path run live in the browser and
  reach external resources (cdnjs, your MISP instance). MISP requires CORS to be
  enabled on the server side.
- The backend binary is built against glibc 2.34 (RHEL 9.x). It will not run on
  older glibc.
- `dig`/`whois`/`nmap` must be installed for host analysis (the installer adds
  them on RHEL). The IP scan is a full `-p-` sweep and can be slow.

---

## License

Copyright (C) 2026 vmarik.

IoCHub is free software, licensed under the GNU General Public License v3.0 or
later. This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See [`LICENSE`](LICENSE) for the full text and
[`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md) for bundled-component
attributions.
