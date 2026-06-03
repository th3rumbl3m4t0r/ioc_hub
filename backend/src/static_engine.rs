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

//! Static analysis engine.
//!
//! Computes file hashes and, for PE (Windows .exe/.dll) files, a structural
//! breakdown — sections, imports, loaded DLLs, compile info, signature
//! presence, strings, embedded domains, and a light packer heuristic. Output is
//! shaped to match VirusTotal's file-object nomenclature (md5/sha1/sha256/
//! ssdeep/authentihash/vhash + pe_info.{imphash,sections,import_list,timestamp,
//! compiler_product_versions} + signature_info, plus extracted names/domains),
//! so the same attribute table and VT search facets apply whether a value came
//! from this engine or from a VT lookup. Last writer wins per field (handled by
//! the caller merging into the entity's attribute map).
//!
//! Everything here is dependency-light and offline: a hand-rolled PE walk over
//! the byte buffer plus RustCrypto digests. No external PE/strings crates.

use md5::Md5;
use serde_json::{json, Map, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Analyze raw file bytes; returns a flat-ish JSON object of VT-style fields.
/// `filename` (if known) seeds `names`/`meaningful_name`.
pub fn analyze(bytes: &[u8], filename: Option<&str>) -> Value {
    let mut out = Map::new();

    // ---- universal hashes (always computed) ------------------------------
    out.insert("md5".into(), json!(hex(&Md5::digest(bytes))));
    out.insert("sha1".into(), json!(hex(&Sha1::digest(bytes))));
    out.insert("sha256".into(), json!(hex(&Sha256::digest(bytes))));
    out.insert("size".into(), json!(bytes.len()));
    if let Some(s) = ssdeep(bytes) {
        out.insert("ssdeep".into(), json!(s));
    }
    if let Some(name) = filename {
        let base = name.rsplit(|c| c == '/' || c == '\\').next().unwrap_or(name);
        if !base.is_empty() {
            out.insert("meaningful_name".into(), json!(base));
            out.insert("names".into(), json!([base]));
        }
    }

    // ---- type (only when we actually recognized it) ---------------------
    let kind = sniff_type(bytes);
    if kind.tag != "unknown" {
        out.insert("type_tag".into(), json!(kind.tag));
        out.insert("type_description".into(), json!(kind.desc));
        if !kind.ext.is_empty() {
            out.insert("type_extension".into(), json!(kind.ext));
        }
    }

    // ---- strings / domains (only when present) ---------------------------
    let strings = extract_strings(bytes, 5);
    let domains = extract_domains(&strings);
    if !domains.is_empty() {
        out.insert("domains".into(), json!(domains));
    }
    if !strings.is_empty() {
        let sample: Vec<&String> = strings.iter().take(400).collect();
        out.insert("strings".into(), json!(sample));
    }

    // whole-file entropy (always computable, genuinely measured)
    out.insert("entropy".into(), json!(round2(shannon_entropy(bytes))));

    // ---- PE-specific -----------------------------------------------------
    if kind.tag == "peexe" || kind.tag == "pedll" {
        if let Some(pe) = parse_pe(bytes) {
            let mut pe_info = Map::new();

            if pe.timestamp != 0 {
                pe_info.insert("timestamp".into(), json!(pe.timestamp));
                // VT also exposes the compile time as creation_date at top level.
                out.insert("creation_date".into(), json!(pe.timestamp));
            }
            if pe.machine != "UNKNOWN" {
                pe_info.insert("machine_type".into(), json!(pe.machine));
            }
            if pe.entry_point != 0 {
                pe_info.insert("entry_point".into(), json!(pe.entry_point));
            }
            if !pe.imphash.is_empty() {
                pe_info.insert("imphash".into(), json!(pe.imphash));
            }

            // sections (VT: name, virtual_address, virtual_size, raw_size, entropy, md5)
            let sections: Vec<Value> = pe.sections.iter().map(|s| json!({
                "name": s.name,
                "virtual_address": s.vaddr,
                "virtual_size": s.vsize,
                "raw_size": s.raw_size,
                "entropy": round2(s.entropy),
                "md5": s.md5,
                "flags": s.flags,
            })).collect();
            if !sections.is_empty() {
                pe_info.insert("sections".into(), json!(sections));
                let names: Vec<&String> = pe.sections.iter().map(|s| &s.name).collect();
                out.insert("section_names".into(), json!(names));
            }

            // imports: VT import_list = [{library_name, imported_functions:[..]}]
            if !pe.imports.is_empty() {
                let import_list: Vec<Value> = pe.imports.iter().map(|(lib, fns)| json!({
                    "library_name": lib,
                    "imported_functions": fns,
                })).collect();
                pe_info.insert("import_list".into(), json!(import_list));
                let dlls: Vec<&String> = pe.imports.iter().map(|(lib, _)| lib).collect();
                out.insert("loaded_dlls".into(), json!(dlls));
            }

            if pe.is_dll {
                pe_info.insert("is_dll".into(), json!(true));
            }
            // Only attach pe_info if it actually has content.
            if !pe_info.is_empty() {
                out.insert("pe_info".into(), json!(pe_info));
            }

            // authentihash (PE-specific SHA256 over the image minus checksum +
            // cert table). Only meaningful for PE.
            if let Some(ah) = authentihash(bytes, &pe) {
                out.insert("authentihash".into(), json!(ah));
            }

            // signature_info: parse the embedded Authenticode certificate chain
            // and surface the signer(s) the way VT does — subject CNs joined
            // leaf→root with "; ". Leaf cert supplies issuer/serial/validity.
            // Nothing is emitted if we can't parse a chain (no placeholder), and
            // validity is only attached if a check succeeds (silent otherwise).
            if let Some((off, size)) = pe.cert_table {
                let region = slice(bytes, off, size);
                let chain = parse_authenticode(region);
                if !chain.is_empty() {
                    let mut sig = Map::new();
                    // signers: chain of subject CNs (leaf first), joined with "; "
                    let signers: Vec<String> = chain.iter()
                        .filter_map(|c| c.subject_cn.clone())
                        .collect();
                    if !signers.is_empty() {
                        sig.insert("signers".into(), json!(signers.join("; ")));
                    }
                    let leaf = &chain[0];
                    if let Some(v) = leaf.subject_o.clone() { sig.insert("signers_details_org".into(), json!(v)); }
                    if let Some(v) = leaf.issuer_cn.clone() { sig.insert("x509_issuer".into(), json!(v)); }
                    if let Some(v) = leaf.issuer_o.clone() { sig.insert("x509_issuer_org".into(), json!(v)); }
                    if let Some(v) = leaf.serial.clone() { sig.insert("x509_serial_number".into(), json!(v)); }
                    if let Some(v) = leaf.not_before.clone() { sig.insert("x509_not_valid_before".into(), json!(v)); }
                    if let Some(v) = leaf.not_after.clone() { sig.insert("x509_not_valid_after".into(), json!(v)); }
                    if let Some(valid) = verify_signature_silent(region) {
                        sig.insert("verified".into(), json!(if valid { "valid" } else { "invalid" }));
                    }
                    if !sig.is_empty() {
                        out.insert("signature_info".into(), json!(sig));
                    }
                }
            }

            // packer heuristic (entropy + telltale section names)
            if let Some(packer) = detect_packer(&pe, bytes) {
                out.insert("packers".into(), json!([packer]));
                push_tag(&mut out, "packed");
            }

            // capability tags from notable imports
            tag_from_imports(&mut out, &pe);
        }
    }

    Value::Object(out)
}

/* ============================== hashing ================================= */

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/* ============================== PE parser =============================== */

struct PeSection {
    name: String,
    vaddr: u32,
    vsize: u32,
    raw_ptr: u32,
    raw_size: u32,
    entropy: f64,
    md5: String,
    flags: u32,
}

struct Pe {
    is_dll: bool,
    machine: String,
    timestamp: u32,
    entry_point: u32,
    sections: Vec<PeSection>,
    imports: Vec<(String, Vec<String>)>,
    imphash: String,
    /// (checksum field file offset) for authentihash exclusion
    checksum_off: usize,
    /// (security dir RVA/offset, size) — for PE this is a *file offset*, not RVA
    cert_table: Option<(u32, u32)>,
    /// file offset of the IMAGE_OPTIONAL_HEADER data-directory array
    is_pe32_plus: bool,
}

fn rd_u16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn parse_pe(b: &[u8]) -> Option<Pe> {
    if b.len() < 0x40 || &b[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = rd_u32(b, 0x3c)? as usize;
    if b.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let machine_raw = rd_u16(b, coff)?;
    let num_sections = rd_u16(b, coff + 2)? as usize;
    let timestamp = rd_u32(b, coff + 4)?;
    let opt_size = rd_u16(b, coff + 16)? as usize;
    let characteristics = rd_u16(b, coff + 18)?;
    let is_dll = characteristics & 0x2000 != 0;

    let opt = coff + 20;
    let magic = rd_u16(b, opt)?;
    let is_plus = magic == 0x20b; // PE32+
    let entry_point = rd_u32(b, opt + 16).unwrap_or(0);

    // checksum lives at offset 64 in the optional header (both PE32/PE32+)
    let checksum_off = opt + 64;

    // data directory starts after the fixed part of the optional header:
    //   PE32:  96 bytes, PE32+: 112 bytes, then NumberOfRvaAndSizes (u32) precedes it.
    let dd_off = if is_plus { opt + 112 } else { opt + 96 };
    // security directory is index 4 (8 bytes each: RVA, size). For the cert
    // table the "RVA" is actually a file offset.
    let sec_dir = dd_off + 4 * 8;
    let cert_table = match (rd_u32(b, sec_dir), rd_u32(b, sec_dir + 4)) {
        (Some(off), Some(size)) if size > 0 => Some((off, size)),
        _ => None,
    };

    // section headers follow the optional header
    let sec_table = opt + opt_size;
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let s = sec_table + i * 40;
        let raw_name = b.get(s..s + 8)?;
        let name = String::from_utf8_lossy(raw_name).trim_end_matches('\0').trim_end_matches(char::from(0)).trim().to_string();
        let vsize = rd_u32(b, s + 8).unwrap_or(0);
        let vaddr = rd_u32(b, s + 12).unwrap_or(0);
        let raw_size = rd_u32(b, s + 16).unwrap_or(0);
        let raw_ptr = rd_u32(b, s + 20).unwrap_or(0);
        let flags = rd_u32(b, s + 36).unwrap_or(0);
        let data = slice(b, raw_ptr, raw_size);
        sections.push(PeSection {
            name,
            vaddr,
            vsize,
            raw_ptr,
            raw_size,
            entropy: shannon_entropy(data),
            md5: hex(&Md5::digest(data)),
            flags,
        });
    }

    // imports (import directory is data dir index 1)
    let imp_dir = dd_off + 1 * 8;
    let imp_rva = rd_u32(b, imp_dir).unwrap_or(0);
    let imports = parse_imports(b, &sections, imp_rva).unwrap_or_default();
    let imphash = compute_imphash(&imports);

    Some(Pe {
        is_dll,
        machine: machine_name(machine_raw),
        timestamp,
        entry_point,
        sections,
        imports,
        imphash,
        checksum_off,
        cert_table,
        is_pe32_plus: is_plus,
    })
}

fn slice(b: &[u8], off: u32, size: u32) -> &[u8] {
    let o = off as usize;
    let e = o.saturating_add(size as usize).min(b.len());
    if o >= b.len() || o >= e { &[] } else { &b[o..e] }
}

fn machine_name(m: u16) -> String {
    match m {
        0x014c => "I386",
        0x8664 => "AMD64",
        0x01c0 => "ARM",
        0xaa64 => "ARM64",
        0x0200 => "IA64",
        _ => "UNKNOWN",
    }
    .to_string()
}

/// Map a virtual address to a file offset using the section table.
fn rva_to_off(sections: &[PeSection], rva: u32) -> Option<u32> {
    for s in sections {
        if rva >= s.vaddr && rva < s.vaddr.saturating_add(s.vsize.max(s.raw_size)) {
            return Some(s.raw_ptr + (rva - s.vaddr));
        }
    }
    None
}

fn read_cstr(b: &[u8], off: u32) -> String {
    let o = off as usize;
    let mut end = o;
    while end < b.len() && b[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(b.get(o..end).unwrap_or(&[])).to_string()
}

fn parse_imports(b: &[u8], sections: &[PeSection], imp_rva: u32) -> Option<Vec<(String, Vec<String>)>> {
    if imp_rva == 0 {
        return None;
    }
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let base = rva_to_off(sections, imp_rva)?;
    // IMAGE_IMPORT_DESCRIPTOR is 20 bytes; array terminated by an all-zero entry.
    let mut i = 0u32;
    loop {
        let d = base + i * 20;
        let orig_thunk = rd_u32(b, d as usize)?; // OriginalFirstThunk (INT)
        let name_rva = rd_u32(b, (d + 12) as usize)?;
        let first_thunk = rd_u32(b, (d + 16) as usize)?; // IAT
        if orig_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        if out.len() > 512 {
            break; // safety
        }
        let lib = match rva_to_off(sections, name_rva) {
            Some(o) => read_cstr(b, o),
            None => String::new(),
        };
        if lib.is_empty() {
            i += 1;
            continue;
        }
        // walk the thunk array (prefer INT, fall back to IAT)
        let thunk_rva = if orig_thunk != 0 { orig_thunk } else { first_thunk };
        let mut fns = Vec::new();
        if let Some(mut t_off) = rva_to_off(sections, thunk_rva) {
            // assume 32-bit thunks unless we detect PE32+ (handled by caller width)
            // We support both widths by probing pointer size from section bounds.
            let width = 4u32; // imphash only needs names; ordinals handled below
            let mut guard = 0;
            loop {
                guard += 1;
                if guard > 4096 {
                    break;
                }
                let val = rd_u32(b, t_off as usize)?;
                let val64_hi = rd_u32(b, (t_off + 4) as usize).unwrap_or(0);
                if val == 0 && val64_hi == 0 {
                    break;
                }
                // ordinal flag (top bit of the pointer-sized value)
                let is_ordinal = (val & 0x8000_0000) != 0 && val64_hi == 0;
                let is_ordinal64 = (val64_hi & 0x8000_0000) != 0;
                if is_ordinal || is_ordinal64 {
                    let ord = val & 0xffff;
                    fns.push(format!("ord{}", ord));
                } else {
                    // points to IMAGE_IMPORT_BY_NAME: u16 hint + asciiz name
                    if let Some(n_off) = rva_to_off(sections, val) {
                        let name = read_cstr(b, n_off + 2);
                        if !name.is_empty() {
                            fns.push(name);
                        }
                    }
                }
                // advance by 8 if this image is PE32+, else 4. We detect width by
                // checking whether the hi dword looked like a continuation.
                t_off += if val64_hi != 0 || is_ordinal64 { 8 } else { width };
                if fns.len() > 4096 {
                    break;
                }
            }
        }
        out.push((lib, fns));
        i += 1;
    }
    Some(out)
}

/// PE imphash: md5 over a comma-joined, lowercased list of `dll.function`
/// entries (dll extension stripped), in import-table order. Matches the
/// pefile/VT convention closely enough to match for typical files.
fn compute_imphash(imports: &[(String, Vec<String>)]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (lib, fns) in imports {
        let mut l = lib.to_lowercase();
        for ext in [".dll", ".ocx", ".sys", ".drv", ".exe"] {
            if l.ends_with(ext) {
                l = l[..l.len() - ext.len()].to_string();
                break;
            }
        }
        for f in fns {
            parts.push(format!("{}.{}", l, f.to_lowercase()));
        }
    }
    if parts.is_empty() {
        return String::new();
    }
    hex(&Md5::digest(parts.join(",").as_bytes()))
}

/// authentihash: SHA256 over the PE with the checksum field (4 bytes), the
/// security data-directory entry (8 bytes), and the certificate table region
/// excluded — the Authenticode definition. A common, well-defined hash; VT
/// stores it as `authentihash`.
fn authentihash(b: &[u8], pe: &Pe) -> Option<String> {
    let mut h = Sha256::new();
    let cks = pe.checksum_off;
    // The security dir entry sits at data-dir index 4. Recompute its offset:
    // dd_off depends on PE32/PE32+; reconstruct from checksum_off (= opt+64).
    let opt = cks - 64;
    let dd_off = if pe.is_pe32_plus { opt + 112 } else { opt + 96 };
    let sec_dir = dd_off + 4 * 8;

    // Build the list of byte ranges to hash, skipping checksum(4) and secdir(8).
    // Region 1: start .. checksum
    // Region 2: checksum+4 .. secdir
    // Region 3: secdir+8 .. cert_table_start (or EOF if no cert)
    // (the certificate table itself, at the end, is excluded)
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut cur = 0usize;
    let push = |ranges: &mut Vec<(usize, usize)>, a: usize, z: usize| {
        if z > a && a <= b.len() {
            ranges.push((a, z.min(b.len())));
        }
    };
    push(&mut ranges, cur, cks);
    cur = cks + 4;
    push(&mut ranges, cur, sec_dir);
    cur = sec_dir + 8;
    let end = match pe.cert_table {
        Some((off, _)) if (off as usize) <= b.len() && off as usize > cur => off as usize,
        _ => b.len(),
    };
    push(&mut ranges, cur, end);

    for (a, z) in ranges {
        h.update(&b[a..z]);
    }
    Some(hex(&h.finalize()))
}

/* ===================== strings / domains / entropy ===================== */

fn extract_strings(b: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    // ASCII
    let mut cur = String::new();
    for &c in b {
        if (0x20..0x7f).contains(&c) {
            cur.push(c as char);
        } else {
            if cur.len() >= min_len {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
        if out.len() > 50_000 {
            break;
        }
    }
    if cur.len() >= min_len {
        out.push(cur);
    }
    // UTF-16LE (common in PE): bytes like X 00 X 00
    let mut cur16 = String::new();
    let mut i = 0;
    while i + 1 < b.len() {
        let c = b[i];
        let hi = b[i + 1];
        if hi == 0 && (0x20..0x7f).contains(&c) {
            cur16.push(c as char);
            i += 2;
        } else {
            if cur16.len() >= min_len {
                out.push(std::mem::take(&mut cur16));
            } else {
                cur16.clear();
            }
            i += 1;
        }
        if out.len() > 80_000 {
            break;
        }
    }
    if cur16.len() >= min_len {
        out.push(cur16);
    }
    out
}

/// Pull plausible domain names out of the extracted strings.
fn extract_domains(strings: &[String]) -> Vec<String> {
    let tlds = [
        "com", "net", "org", "info", "biz", "ru", "cn", "io", "co", "xyz", "top", "online",
        "site", "club", "shop", "gov", "edu", "mil", "uk", "de", "fr", "nl", "br", "in", "ir",
        "su", "pw", "cc", "tk", "ml", "ga", "cf", "us", "eu", "me", "to", "ws", "name", "pro",
    ];
    let mut found: Vec<String> = Vec::new();
    for s in strings {
        for tok in s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
            let t = tok.trim_matches('.').to_lowercase();
            if t.len() < 4 || t.len() > 253 || !t.contains('.') {
                continue;
            }
            // must look like label.label(.label)*; last label a known-ish TLD
            let labels: Vec<&str> = t.split('.').collect();
            if labels.len() < 2 || labels.iter().any(|l| l.is_empty() || l.len() > 63) {
                continue;
            }
            let tld = *labels.last().unwrap();
            if !tlds.contains(&tld) {
                continue;
            }
            if !labels.iter().all(|l| l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')) {
                continue;
            }
            // skip things that are obviously version strings / not hostnames
            if labels[0].chars().all(|c| c.is_ascii_digit()) && labels.len() == 2 {
                continue;
            }
            if !found.iter().any(|x| x == &t) {
                found.push(t);
            }
            if found.len() > 200 {
                return found;
            }
        }
    }
    found
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut ent = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            ent -= p * p.log2();
        }
    }
    ent
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/* ============================ packer / tags ============================ */

fn detect_packer(pe: &Pe, _b: &[u8]) -> Option<String> {
    // Section-name signatures.
    for s in &pe.sections {
        let n = s.name.to_uppercase();
        if n.starts_with("UPX") {
            return Some("UPX".into());
        }
        if n.contains("ASPACK") {
            return Some("ASPack".into());
        }
        if n == ".PETITE" || n.contains("PETITE") {
            return Some("Petite".into());
        }
        if n == ".MPRESS1" || n == ".MPRESS2" {
            return Some("MPRESS".into());
        }
        if n == ".THEMIDA" || n.contains("WINLICE") {
            return Some("Themida/WinLicense".into());
        }
        if n == ".VMP0" || n == ".VMP1" || n.contains("VMP") {
            return Some("VMProtect".into());
        }
    }
    // High mean entropy of code/data sections is a generic packed signal.
    let code: Vec<&PeSection> = pe.sections.iter().filter(|s| s.raw_size > 0).collect();
    if !code.is_empty() {
        let avg = code.iter().map(|s| s.entropy).sum::<f64>() / code.len() as f64;
        let high = code.iter().filter(|s| s.entropy > 7.2).count();
        if avg > 7.0 && high >= 1 {
            return Some("high-entropy (possible packer/crypter)".into());
        }
    }
    None
}

fn push_tag(out: &mut Map<String, Value>, tag: &str) {
    let arr = out.entry("tags".to_string()).or_insert_with(|| json!([]));
    if let Some(a) = arr.as_array_mut() {
        if !a.iter().any(|t| t.as_str() == Some(tag)) {
            a.push(json!(tag));
        }
    }
}

/// Cheap capability tags from notable imports (mirrors VT's "tags" vibe).
fn tag_from_imports(out: &mut Map<String, Value>, pe: &Pe) {
    let mut all_fns: Vec<String> = Vec::new();
    for (_, fns) in &pe.imports {
        for f in fns {
            all_fns.push(f.to_lowercase());
        }
    }
    let has = |needle: &str| all_fns.iter().any(|f| f.contains(needle));
    if has("virtualalloc") && has("createremotethread") {
        push_tag(out, "code-injection");
    }
    if has("internetopen") || has("winhttp") || has("wsastartup") || has("send") {
        push_tag(out, "network");
    }
    if has("cryptencrypt") || has("cryptacquirecontext") || has("bcryptencrypt") {
        push_tag(out, "crypto");
    }
    if has("regsetvalue") || has("regcreatekey") {
        push_tag(out, "persistence");
    }
}

/* =============================== ssdeep ================================ */
//
// A from-scratch implementation of the ssdeep/spamsum fuzzy hash. ssdeep splits
// the input at content-dependent boundaries using a rolling hash, hashing each
// piece with a FNV-style hash down to one base64 character, at two block sizes
// (b and 2b). Output: "blocksize:hash1:hash2". This follows the public spamsum
// algorithm; it interoperates with other ssdeep implementations for comparison.

const SPAMSUM_LENGTH: usize = 64;
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HASH_PRIME: u32 = 0x0100_0193;
const HASH_INIT: u32 = 0x2801_9456;
const ROLL_WINDOW: usize = 7;

struct Roll {
    window: [u8; ROLL_WINDOW],
    h1: u32,
    h2: u32,
    h3: u32,
    n: usize,
}
impl Roll {
    fn new() -> Self {
        Roll { window: [0; ROLL_WINDOW], h1: 0, h2: 0, h3: 0, n: 0 }
    }
    fn hash(&mut self, c: u8) -> u32 {
        self.h2 = self.h2.wrapping_sub(self.h1).wrapping_add((ROLL_WINDOW as u32).wrapping_mul(c as u32));
        self.h1 = self.h1.wrapping_add(c as u32).wrapping_sub(self.window[self.n % ROLL_WINDOW] as u32);
        self.window[self.n % ROLL_WINDOW] = c;
        self.n = self.n.wrapping_add(1);
        self.h3 = self.h3 << 5;
        self.h3 ^= c as u32;
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

fn fnv(mut h: u32, c: u8) -> u32 {
    h = h.wrapping_mul(HASH_PRIME);
    h ^= c as u32;
    h
}

fn ssdeep(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    // pick an initial block size so the signature fits in SPAMSUM_LENGTH
    let mut block_size: u64 = 3;
    while block_size * (SPAMSUM_LENGTH as u64) < data.len() as u64 {
        block_size *= 2;
    }

    loop {
        let bs = block_size.max(3);
        let mut roll = Roll::new();
        let mut h1 = HASH_INIT;
        let mut h2 = HASH_INIT;
        let mut sig1 = Vec::with_capacity(SPAMSUM_LENGTH);
        let mut sig2 = Vec::with_capacity(SPAMSUM_LENGTH / 2);

        for &c in data {
            let r = roll.hash(c) as u64;
            h1 = fnv(h1, c);
            h2 = fnv(h2, c);
            // boundary for block size bs
            if (r % bs) == (bs - 1) {
                if sig1.len() < SPAMSUM_LENGTH - 1 {
                    sig1.push(B64[(h1 % 64) as usize]);
                    h1 = HASH_INIT;
                }
            }
            // boundary for block size 2*bs
            if (r % (bs * 2)) == (bs * 2 - 1) {
                if sig2.len() < SPAMSUM_LENGTH / 2 - 1 {
                    sig2.push(B64[(h2 % 64) as usize]);
                    h2 = HASH_INIT;
                }
            }
        }
        // tail characters from the final hash state
        sig1.push(B64[(h1 % 64) as usize]);
        sig2.push(B64[(h2 % 64) as usize]);

        // If the signature is too short and we can halve the block size, retry.
        if bs > 3 && sig1.len() < SPAMSUM_LENGTH / 2 {
            block_size /= 2;
            continue;
        }
        let s1 = String::from_utf8_lossy(&sig1).to_string();
        let s2 = String::from_utf8_lossy(&sig2).to_string();
        return Some(format!("{}:{}:{}", bs, s1, s2));
    }
}

/* ============================ type sniffing ============================ */

struct Kind {
    tag: &'static str,
    desc: &'static str,
    ext: &'static str,
}

fn sniff_type(b: &[u8]) -> Kind {
    if b.len() >= 2 && &b[0..2] == b"MZ" {
        // Decide exe vs dll once the PE header is parsed; default exe here.
        let is_dll = parse_pe(b).map(|p| p.is_dll).unwrap_or(false);
        if is_dll {
            return Kind { tag: "pedll", desc: "PE32 dynamic link library", ext: "dll" };
        }
        return Kind { tag: "peexe", desc: "PE32 executable", ext: "exe" };
    }
    if b.len() >= 4 && &b[0..4] == b"\x7fELF" {
        return Kind { tag: "elf", desc: "ELF executable", ext: "" };
    }
    if b.len() >= 4 && (&b[0..4] == b"\xfe\xed\xfa\xce" || &b[0..4] == b"\xfe\xed\xfa\xcf"
        || &b[0..4] == b"\xcf\xfa\xed\xfe" || &b[0..4] == b"\xce\xfa\xed\xfe") {
        return Kind { tag: "macho", desc: "Mach-O executable", ext: "" };
    }
    if b.len() >= 4 && &b[0..4] == b"%PDF" {
        return Kind { tag: "pdf", desc: "PDF document", ext: "pdf" };
    }
    if b.len() >= 2 && &b[0..2] == b"PK" {
        return Kind { tag: "zip", desc: "ZIP archive (or OOXML/JAR/APK)", ext: "zip" };
    }
    Kind { tag: "unknown", desc: "data", ext: "" }
}


/// Best-effort Authenticode validity check. True validation requires building
/// and verifying the certificate chain against a trust store plus checking the
/// signed PE hash — not something we can do reliably offline. Rather than emit a
/// misleading verdict, this returns None (so the caller omits `verified`). The
/// hook exists so a real implementation can be dropped in later; on any failure
/// it must stay silent and return None.
fn verify_signature_silent(_cert_region: &[u8]) -> Option<bool> {
    None
}

/* ===================== Authenticode certificate parsing ================= */
//
// The PE certificate table (security directory) contains one or more
// WIN_CERTIFICATE structures; for Authenticode the payload is a PKCS#7
// SignedData (DER) that embeds the signer's X.509 certificate(s). We do a
// minimal, dependency-free DER walk to pull the human-useful fields: the
// signer's subject and issuer (CN/O), serial number, and validity dates.
//
// This is deliberately tolerant: anything we can't parse is simply omitted.
// We do NOT claim chain validity (that needs a trust store + path validation);
// per request, if we can't establish something we leave it out entirely rather
// than emit a placeholder.

/// A minimal parsed view of an X.509 certificate.
#[derive(Default)]
struct CertInfo {
    subject_cn: Option<String>,
    subject_o: Option<String>,
    issuer_cn: Option<String>,
    issuer_o: Option<String>,
    serial: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
}

/// One DER TLV.
struct Tlv<'a> {
    tag: u8,
    /// content bytes (not including tag/length)
    content: &'a [u8],
    /// total bytes consumed (tag+len+content)
    total: usize,
}

/// Parse a single DER TLV at the front of `b`.
fn der_tlv(b: &[u8]) -> Option<Tlv<'_>> {
    if b.len() < 2 {
        return None;
    }
    let tag = b[0];
    let first = b[1];
    let (len, hdr) = if first & 0x80 == 0 {
        (first as usize, 2usize)
    } else {
        let nbytes = (first & 0x7f) as usize;
        if nbytes == 0 || nbytes > 4 || b.len() < 2 + nbytes {
            return None;
        }
        let mut l = 0usize;
        for i in 0..nbytes {
            l = (l << 8) | b[2 + i] as usize;
        }
        (l, 2 + nbytes)
    };
    if b.len() < hdr + len {
        return None;
    }
    Some(Tlv { tag, content: &b[hdr..hdr + len], total: hdr + len })
}

/// Iterate the TLVs inside a constructed value's content.
fn der_children(content: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        match der_tlv(rest) {
            Some(t) => {
                let adv = t.total;
                out.push(t);
                if adv == 0 || adv > rest.len() {
                    break;
                }
                rest = &rest[adv..];
            }
            None => break,
        }
    }
    out
}

/// Recursively collect ALL X.509 certificates found in the DER tree. A
/// certificate is recognized by structure: SEQUENCE { SEQUENCE(tbs),
/// SEQUENCE(sigAlg), BIT STRING(sig) }. Order of discovery is preserved.
fn collect_certificates(b: &[u8], depth: usize, out: &mut Vec<CertInfo>) {
    if depth > 24 || out.len() > 64 {
        return;
    }
    let mut rest = b;
    while !rest.is_empty() {
        let t = match der_tlv(rest) {
            Some(t) => t,
            None => break,
        };
        let adv = t.total;
        if t.tag == 0x30 {
            let kids = der_children(t.content);
            if kids.len() == 3 && kids[0].tag == 0x30 && kids[2].tag == 0x03 {
                if let Some(ci) = parse_tbs(kids[0].content) {
                    out.push(ci);
                }
            }
            // recurse regardless, so nested SignedData / counter-signatures are seen
            collect_certificates(t.content, depth + 1, out);
        } else if t.tag & 0x20 != 0 {
            collect_certificates(t.content, depth + 1, out);
        }
        if adv == 0 || adv > rest.len() {
            break;
        }
        rest = &rest[adv..];
    }
}

/// Order certificates leaf → root. The leaf is the cert whose subject is not the
/// issuer of any other cert (i.e. nothing is signed by it); then follow issuer
/// links upward. Falls back to discovery order if linkage is ambiguous.
fn order_chain(certs: Vec<CertInfo>) -> Vec<CertInfo> {
    let n = certs.len();
    if n <= 1 {
        return certs;
    }
    // subject of cert i
    let subj = |c: &CertInfo| c.subject_cn.clone().unwrap_or_default();
    let issu = |c: &CertInfo| c.issuer_cn.clone().unwrap_or_default();
    let subjects: Vec<String> = certs.iter().map(|c| subj(c)).collect();
    // a cert is a CA-in-this-set if some other cert's issuer == its subject
    let is_issuer_of_other: Vec<bool> = (0..n)
        .map(|i| {
            let s = &subjects[i];
            !s.is_empty() && certs.iter().enumerate().any(|(j, c)| j != i && &issu(c) == s)
        })
        .collect();
    // leaf candidate: not an issuer of any other; pick the first such
    let start = (0..n).find(|&i| !is_issuer_of_other[i]);
    let mut used = vec![false; n];
    let mut chain = Vec::with_capacity(n);
    if let Some(mut cur) = start {
        loop {
            if used[cur] {
                break;
            }
            used[cur] = true;
            let issuer_name = issu(&certs[cur]);
            chain.push(cur);
            if issuer_name.is_empty() {
                break;
            }
            // self-signed root: issuer == subject -> stop
            if issuer_name == subjects[cur] {
                break;
            }
            match (0..n).find(|&j| !used[j] && subjects[j] == issuer_name) {
                Some(next) => cur = next,
                None => break,
            }
        }
    }
    // append any not-yet-included certs in discovery order
    for i in 0..n {
        if !used[i] {
            chain.push(i);
        }
    }
    // materialize in chain order (move out of `certs`)
    let mut opt: Vec<Option<CertInfo>> = certs.into_iter().map(Some).collect();
    chain.into_iter().filter_map(|i| opt[i].take()).collect()
}

/// Parse tbsCertificate fields we care about: serial, issuer, validity, subject.
fn parse_tbs(tbs: &[u8]) -> Option<CertInfo> {
    let kids = der_children(tbs);
    if kids.is_empty() {
        return None;
    }
    let mut idx = 0;
    // optional [0] EXPLICIT version
    if kids.get(idx).map(|t| t.tag == 0xA0).unwrap_or(false) {
        idx += 1;
    }
    let mut ci = CertInfo::default();
    // serialNumber INTEGER
    if let Some(t) = kids.get(idx) {
        if t.tag == 0x02 {
            ci.serial = Some(hex(t.content));
        }
        idx += 1;
    }
    // signature AlgorithmIdentifier (SEQUENCE) — skip
    if kids.get(idx).map(|t| t.tag == 0x30).unwrap_or(false) {
        idx += 1;
    }
    // issuer Name (SEQUENCE of RDNs)
    if let Some(t) = kids.get(idx) {
        if t.tag == 0x30 {
            let (cn, o) = parse_name(t.content);
            ci.issuer_cn = cn;
            ci.issuer_o = o;
        }
        idx += 1;
    }
    // validity SEQUENCE { notBefore, notAfter }
    if let Some(t) = kids.get(idx) {
        if t.tag == 0x30 {
            let vk = der_children(t.content);
            if let Some(nb) = vk.get(0) {
                ci.not_before = parse_time(nb);
            }
            if let Some(na) = vk.get(1) {
                ci.not_after = parse_time(na);
            }
        }
        idx += 1;
    }
    // subject Name (SEQUENCE of RDNs)
    if let Some(t) = kids.get(idx) {
        if t.tag == 0x30 {
            let (cn, o) = parse_name(t.content);
            ci.subject_cn = cn;
            ci.subject_o = o;
        }
    }
    Some(ci)
}

/// Extract CN and O from an X.501 Name (SEQUENCE OF RelativeDistinguishedName).
/// Each RDN is a SET OF AttributeTypeAndValue (SEQUENCE { OID, value }).
fn parse_name(name: &[u8]) -> (Option<String>, Option<String>) {
    const OID_CN: &[u8] = &[0x55, 0x04, 0x03]; // 2.5.4.3
    const OID_O: &[u8] = &[0x55, 0x04, 0x0a]; // 2.5.4.10
    let mut cn = None;
    let mut o = None;
    for rdn in der_children(name) {
        if rdn.tag != 0x31 {
            continue; // SET
        }
        for atv in der_children(rdn.content) {
            if atv.tag != 0x30 {
                continue; // SEQUENCE
            }
            let parts = der_children(atv.content);
            if parts.len() < 2 || parts[0].tag != 0x06 {
                continue; // OID + value
            }
            let val = der_string(&parts[1]);
            if parts[0].content == OID_CN && cn.is_none() {
                cn = val;
            } else if parts[0].content == OID_O && o.is_none() {
                o = val;
            }
        }
    }
    (cn, o)
}

/// Decode a DER string TLV (PrintableString/UTF8String/IA5String/etc.).
fn der_string(t: &Tlv) -> Option<String> {
    match t.tag {
        0x0c | 0x13 | 0x14 | 0x16 | 0x1e | 0x80 => {
            let s = String::from_utf8_lossy(t.content).trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        _ => None,
    }
}

/// Decode UTCTime / GeneralizedTime to an ISO-ish date string.
fn parse_time(t: &Tlv) -> Option<String> {
    let raw = String::from_utf8_lossy(t.content);
    let s: String = raw.chars().filter(|c| c.is_ascii_digit() || *c == 'Z').collect();
    // UTCTime: YYMMDDHHMMSSZ ; GeneralizedTime: YYYYMMDDHHMMSSZ
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    let (yyyy, rest) = if t.tag == 0x17 {
        // UTCTime: 2-digit year (>=50 => 19xx, else 20xx)
        if digits.len() < 6 {
            return None;
        }
        let yy: i32 = digits[0..2].parse().ok()?;
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (year, &digits[2..])
    } else {
        // GeneralizedTime: 4-digit year
        if digits.len() < 8 {
            return None;
        }
        let year: i32 = digits[0..4].parse().ok()?;
        (year, &digits[4..])
    };
    if rest.len() < 4 {
        return None;
    }
    let mo = &rest[0..2];
    let da = &rest[2..4];
    let (hh, mm, ss) = if rest.len() >= 10 {
        (&rest[4..6], &rest[6..8], &rest[8..10])
    } else if rest.len() >= 6 {
        (&rest[4..6], "00", "00")
    } else {
        ("00", "00", "00")
    };
    Some(format!("{:04}-{}-{}T{}:{}:{}Z", yyyy, mo, da, hh, mm, ss))
}

/// Given the PE cert-table region, parse all signer certificates and return
/// them ordered leaf → root. Empty vec on any parse failure (caller omits
/// signature_info). The PE may contain multiple WIN_CERTIFICATE entries
/// back-to-back (each 8-byte aligned); we walk them all.
fn parse_authenticode(cert_region: &[u8]) -> Vec<CertInfo> {
    let mut certs: Vec<CertInfo> = Vec::new();
    let mut off = 0usize;
    let mut guard = 0;
    while off + 8 <= cert_region.len() && guard < 16 {
        guard += 1;
        let len = u32::from_le_bytes([
            cert_region[off], cert_region[off + 1], cert_region[off + 2], cert_region[off + 3],
        ]) as usize;
        if len < 8 {
            break;
        }
        let end = (off + len).min(cert_region.len());
        if end <= off + 8 {
            break;
        }
        let pkcs7 = &cert_region[off + 8..end];
        collect_certificates(pkcs7, 0, &mut certs);
        // advance to the next WIN_CERTIFICATE (8-byte aligned)
        let next = (off + len + 7) & !7usize;
        if next <= off {
            break;
        }
        off = next;
    }
    order_chain(certs)
}

