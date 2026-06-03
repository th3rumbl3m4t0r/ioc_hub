# Third-party licenses

IoCHub itself is licensed under the GNU General Public License v3.0 (see
[`LICENSE`](LICENSE)). It bundles and/or loads the third-party components listed
below. Each remains under its own license; those licenses are GPLv3-compatible.

> **Verify before you ship.** The attributions below were compiled by reading
> `Cargo.lock`, the vendored file headers, and well-known upstream licensing.
> They were **not** produced by an automated license scanner in this build
> environment. Before publishing, please confirm them with the authoritative
> tooling:
>
> ```
> cargo install cargo-deny
> cargo deny check licenses        # run in backend/
> ```
>
> and confirm the exact license of the vendored `xlsx.full.min.js` build (see
> the SheetJS note below). If `cargo deny` flags anything, treat its output as
> the source of truth over this file.

---

## Why GPLv3 (not GPLv2)

Several dependencies are licensed under **Apache-2.0** (PDF.js, Tesseract.js,
SheetJS community build, and the Apache halves of the RustCrypto crates).
Apache-2.0 is compatible with **GPLv3** but **not** with GPLv2, because of
Apache-2.0's patent-termination clause. IoCHub is therefore released under
**GPLv3 (or later)**.

---

## Backend — Rust crates

The Rust dependency tree (from `backend/Cargo.lock`) consists of the following
crates. To the best of our knowledge every one is permissively licensed
(`MIT OR Apache-2.0`, or MIT, or BSD-style), all of which are GPLv3-compatible.
The crates and their customary licenses:

| Crate | License (customary) |
|---|---|
| aho-corasick | MIT OR Unlicense |
| argon2 | MIT OR Apache-2.0 |
| ascii | MIT OR Apache-2.0 |
| base64ct | MIT OR Apache-2.0 |
| blake2 | MIT OR Apache-2.0 |
| block-buffer | MIT OR Apache-2.0 |
| cfg-if | MIT OR Apache-2.0 |
| chunked_transfer | Apache-2.0 |
| cpufeatures | MIT OR Apache-2.0 |
| crypto-common | MIT OR Apache-2.0 |
| digest | MIT OR Apache-2.0 |
| generic-array | MIT |
| getrandom | MIT OR Apache-2.0 |
| hmac | MIT OR Apache-2.0 |
| httpdate | MIT OR Apache-2.0 |
| itoa | MIT OR Apache-2.0 |
| libc | MIT OR Apache-2.0 |
| log | MIT OR Apache-2.0 |
| md-5 | MIT OR Apache-2.0 |
| memchr | MIT OR Unlicense |
| password-hash | MIT OR Apache-2.0 |
| pbkdf2 | MIT OR Apache-2.0 |
| proc-macro2 | MIT OR Apache-2.0 |
| quote | MIT OR Apache-2.0 |
| rand_core | MIT OR Apache-2.0 |
| regex | MIT OR Apache-2.0 |
| regex-automata | MIT OR Apache-2.0 |
| regex-syntax | MIT OR Apache-2.0 |
| serde | MIT OR Apache-2.0 |
| serde_core | MIT OR Apache-2.0 |
| serde_derive | MIT OR Apache-2.0 |
| serde_json | MIT OR Apache-2.0 |
| sha1 | MIT OR Apache-2.0 |
| sha2 | MIT OR Apache-2.0 |
| subtle | BSD-3-Clause |
| syn | MIT OR Apache-2.0 |
| tiny_http | MIT OR Apache-2.0 |
| typenum | MIT OR Apache-2.0 |
| unicode-ident | (MIT OR Apache-2.0) AND Unicode-DFS-2016 |
| version_check | MIT OR Apache-2.0 |
| wasi | MIT OR Apache-2.0 OR Apache-2.0-WITH-LLVM-exception |
| zmij | MIT OR Apache-2.0 |

Notable authors/projects to credit:
- **The RustCrypto project** — argon2, password-hash, pbkdf2, sha1, sha2, md-5,
  hmac, digest, block-buffer, crypto-common, blake2, base64ct, subtle,
  generic-array, typenum, cpufeatures, rand_core.
- **The Rust Project Developers / rust-lang** — libc, getrandom, log, regex,
  regex-automata, regex-syntax, cfg-if, hashbrown-style utilities.
- **David Tolnay** — serde, serde_json, serde_derive, proc-macro2, quote, syn,
  itoa, unicode-ident.
- **Andrew Gallant (BurntSushi)** — aho-corasick, memchr.
- **tiny_http authors** — tiny_http, ascii, chunked_transfer, httpdate.

(`unicode-ident` additionally includes data under the Unicode-DFS-2016 license;
`wasi` is only pulled in for the `getrandom` WASI target and is not used on the
RHEL/Linux build target.)

---

## Frontend — vendored libraries (shipped in `frontend/vendor/`)

| Library | Version | License | Copyright / project |
|---|---|---|---|
| Cytoscape.js | 3.30.2 | MIT | © 2016–2024 The Cytoscape Consortium |
| SheetJS (xlsx) | 0.18.x (community build) | Apache-2.0 | © 2012–present SheetJS LLC |

**SheetJS note:** the vendored `xlsx.full.min.js` shows only a copyright banner
in its minified header. The SheetJS **community** distribution is Apache-2.0
(GPLv3-compatible). Confirm you are shipping the community build (not a
commercial "SheetJS Pro" build) before release; if in doubt, re-fetch the
community build from the official SheetJS CDN/repository.

---

## Frontend — libraries loaded on demand (report extractor)

The report-upload feature (`frontend/report-engine.js`) loads the following from
a CDN **only when the report pane is opened**, and removes them when it closes.
They are not bundled, but because IoCHub ships code that loads and calls them,
their notices are reproduced here:

| Library | Version | License | Project |
|---|---|---|---|
| PDF.js | 3.11.174 | Apache-2.0 | Mozilla Foundation |
| Mammoth.js | 1.8.0 | BSD-2-Clause | Michael Williamson |
| Tesseract.js | 5.1.0 | Apache-2.0 | Tesseract.js contributors |

Tesseract.js wraps the Tesseract OCR engine (Apache-2.0, Google Inc. and
contributors) and downloads language trained-data at runtime from
`tessdata.projectnaptha.com`.

---

## External services (no bundled code)

IoCHub communicates over the network with services you configure, but bundles
none of their code, so they impose no license obligation on this distribution:
VirusTotal API, MISP, CAPE Sandbox, Palo Alto Cortex XSIAM/XQL, and Microsoft
Entra ID. Use of those services is governed by their own terms.

---

## Full license texts

- IoCHub's GPLv3 text: see [`LICENSE`](LICENSE).
- The MIT, Apache-2.0, BSD-2-Clause, and BSD-3-Clause license texts apply to the
  components above as indicated. The Apache-2.0 components additionally require
  retaining their `NOTICE` files where provided; consult each upstream project.
