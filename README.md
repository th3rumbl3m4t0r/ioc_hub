# IoCHub

A browser-first platform for connecting Indicators of Compromise (IoCs) into a
relationship graph — files → domains → hosting IPs → more domains → more files —
with VirusTotal and MISP enrichment, checkbox-driven pivoting, on-demand report
extraction, and XLSX / MISP / PNG / PDF export.

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

```bash
cd backend
cargo build --release      # -> target/release/iochub
```

The frontend is static; no build step.

---

## Security model

- **Zero-knowledge credentials.** The browser derives two PBKDF2-HMAC-SHA256
  (210k iterations) values from your password: an *auth secret* (login
  credential, stored on the server only as an Argon2id hash) and an *AES-GCM
  content key* that **never leaves the browser**. Graphs and your VirusTotal/
  MISP API keys are stored on the server only as AES-GCM ciphertext, decrypted
  in the browser. A page reload requires logging in again.
- **IP-bound sessions.** A session token is tied to the source IP; a request
  from a different IP is rejected.
- **Optional JA3 fallback (for egress proxies like Zscaler).** When a TLS JA3
  fingerprint is supplied by a trusted edge (`IOCHUB_JA3_HEADER`), a session may
  survive a source-IP change if the fingerprint matches. The backend cannot
  compute JA3 itself (Apache terminates TLS); see `deploy/JA3-SETUP.md`. Unset =
  pure IP binding.
- **Login throttle.** Permissive per-IP backstop against brute force: 150 failed
  logins within an hour blocks that IP for 24 hours (in-memory; resets on
  restart).
- **Admin-only account creation.** No open registration.
- **API keys never hit the server in clear.** The VirusTotal key travels
  per-request through a same-origin relay (VT has no CORS); the MISP key is used
  for direct browser->MISP queries (MISP supports CORS).

### Azure / Entra ID SSO — NOT finished (disabled by default)

The Entra ID single-sign-on path is an **unfinished skeleton** and is **disabled
by default**. It only runs if you set `IOCHUB_ENABLE_SSO=1`, and you should not
do that in production yet: the SSO endpoint decodes the Entra JWT to read the
tenant id but **does not verify the token signature** (or `aud`/`iss`/`exp`)
against the tenant's JWKS. Until that verification is implemented, an attacker
who can reach the server could forge a token, so SSO must stay off. Local
zero-knowledge accounts are the supported login method.

---

## Features

### Graph & UI
- Cytoscape graph styled minimally (BlackArch/X11 feel); day/night toggle
  switches the graph background. Single user-adjustable accent colour.
- Collapsible panes: graph storage and entity lists. Two user graph slots plus
  an autosave slot.
- **Layered selection highlight** and a **task-running halo** on entities with
  work in flight.
- **Clump layout** (re-layout button) groups entities by topology/attributes;
  adding entities otherwise drops them into open space.
- **Right-click context menus** mirroring the details-pane actions, plus
  per-relationship expand actions with in-graph/on-VT counts.

### Enrichment & pivoting
- **VirusTotal** object enrichment + relationship expansion with in-graph/on-VT
  counts (resolved IPs are added as direct `resolutions` edges, VT-expand style).
- **MISP**: query any entity directly from the browser. Hashes merge under the
  same keys as VirusTotal (cross-checkable, VT can overwrite); tags/comments/
  categories become `misp.*`; events and galaxies spawn as sub-entities.
  Optional auto-enrich queries every newly added entity.
- **Checkbox pivoting** (incl. combinations) into VT Intelligence searches;
  pivot sub-entities remember their query and offer a one-click re-run.
- **Static analysis** (PE parser + hashes + Authenticode signer chain).
- **Host analysis**: domains via `dig`/`whois`/TLS cert; IPs via `whois`, the
  server's TLS certificate (openssl), and an `nmap` full-port scan.
- **CAPE sandbox** over REST (you run CAPE; per-user regex allow-list).
- **Autopivot** with per-type rules and sensitivity gates.

### Report extraction (PDF/DOCX)
- An isolated report pane loads PDF.js/Mammoth/Tesseract from a CDN **only when
  opened** and tears them down on close. Two-pass text + OCR; extracts
  hashes/IPs/domains/URLs (defanged) and signer/ASN/registrar sub-entities.

### Export
- **XLSX**: one sheet per entity type + a relations sheet, columns ordered
  per type (hashes/`meaningful_name` for files; `as_owner`/`asn`/`whois` for IPs;
  `registrar`/`whois` for domains), then pivot/connection attributes, then the
  rest. Unix timestamps render as ISO-8601.
- **MISP**: a MISP event JSON — files as `file` objects (hashes + filenames),
  domains/IPs/URLs as typed network attributes; meaningful indicators only.
- **PNG**: the graph as a high-resolution image (≈50px margin around the
  furthest entities, respects the accent and day/night background, no fixed
  resolution cap).
- **PDF**: a report styled to match the IoCHub interface (monospace, your accent
  colour) — the graph on page 1, then every entity with the same indicator info
  as the MISP export plus the connections it made, then a full connection
  listing. Rendered client-side with jsPDF; no external fonts or images are
  embedded.

### XSIAM / XQL
- Per-entity and **bulk** XQL generation for a Cortex XSIAM tenant: equality →
  `in (...)`, "contains" → regexp (`~=`), file names/paths via
  `action_process_image_path`. Copy-only.

---

## Configuration

| Env var | Purpose | Default |
|---|---|---|
| `IOCHUB_ADDR` | backend bind address | `127.0.0.1:8787` |
| `IOCHUB_DATA` | data dir (accounts, graphs, keys) | `./data` |
| `IOCHUB_PUBLIC` | static frontend dir | `./public` |
| `IOCHUB_ADMIN_PASSWORD` | seed admin password (first start only) | `IoChUb` |
| `IOCHUB_THREADS` | worker threads | `8` |
| `IOCHUB_JA3_HEADER` | trusted JA3 header for the IP-change fallback | unset (off) |
| `IOCHUB_ENABLE_SSO` | enable Entra ID SSO endpoint (skeleton — leave off) | off |
| `IOCHUB_ENTRA_TENANT` | Entra tenant id override | placeholder |

**MISP** instance URL + API key are set in Settings. Because MISP queries run
directly from the browser, add your MISP origin to the `connect-src` in
`/etc/httpd/conf.d/iochub-le-ssl.conf` and reload httpd (none allowed by
default).

**CAPE** is configured in `<data>/cape.conf`. Set the CAPE side's
`ratelimit=no` for polling to work.

---

## Repository layout

```
backend/        Rust backend (single binary)
  src/          main, auth, store, vt, cape, static_engine, host_analysis, http_util
frontend/       static app
  index.html, app.css, app.js, report-engine.js, pdf-export.js
  vendor/       cytoscape.min.js, xlsx.full.min.js, jspdf.umd.min.js  (vendored)
deploy/         deploy.sh (fresh-install RHEL 9.8), vhosts, systemd unit, JA3-SETUP.md
LICENSE                     GPLv3
THIRD-PARTY-LICENSES.md     dependency attributions
```

---

## Caveats

- **Azure/Entra SSO is unfinished** and disabled by default — see the security
  section. Do not enable it in production.
- The report extractor's OCR and the MISP query path run live in the browser and
  reach external resources (cdnjs, your MISP instance). MISP requires CORS
  enabled server-side.
- The backend binary is built against glibc 2.34 (RHEL 9.x); it will not run on
  older glibc.
- `dig`/`whois`/`nmap` must be installed for host analysis (the installer adds
  them on RHEL). The IP scan is a full `-p-` sweep and can be slow.

---

## License

Copyright (C) 2026 vmarik.

IoCHub is free software, licensed under the GNU General Public License v3.0 or
later. Distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See [`LICENSE`](LICENSE) and [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md).
