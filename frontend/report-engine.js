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

/*
  IoCHub report extraction engine — LOADED ON DEMAND, REMOVABLE.

  This file is NOT part of the base bundle. The app injects it (as a <script>)
  only when the report pane opens, and removes it — together with the CDN
  scripts it pulls (PDF.js / Mammoth / Tesseract) and any Tesseract workers —
  when the pane closes. So none of this heavy machinery sits in memory during
  normal use, and if the CDNs are unreachable only report upload is affected.

  Public API (attached to window.IoCHubReport):
    run(file, hooks)  -> Promise<result|null>
        hooks: { log(msg,cls), status(msg), prog(pct), counts(io,hints,basis) }
        result: { reportName, basis, hashes, ips, domains, urls,
                  signers, asns, registrars, textLength }
    teardown()        -> removes injected CDN <script>s + terminates workers
*/
(function () {
  "use strict";

  var CDN = {
    mammoth: 'https://cdnjs.cloudflare.com/ajax/libs/mammoth/1.8.0/mammoth.browser.min.js',
    pdfjs:   'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js',
    pdfworker: 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js',
    tesseract: 'https://cdnjs.cloudflare.com/ajax/libs/tesseract.js/5.1.0/tesseract.min.js',
  };

  var injected = [];      // <script> elements we added (for teardown)
  var pdfjsLib = null;

  function loadScript(src) {
    return new Promise(function (res, rej) {
      var s = document.createElement('script');
      s.src = src; s.dataset.iochubReport = '1';
      s.onload = res; s.onerror = function () { rej(new Error('failed to load ' + src)); };
      document.head.appendChild(s);
      injected.push(s);
    });
  }

  /* ---- IoC extraction (mirrors the app's detectKind patterns) ---- */
  function refang(t) {
    return (t || '')
      .replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.').replace(/\{\.\}/g, '.')
      .replace(/\[dot\]/gi, '.').replace(/\s+dot\s+/gi, '.')
      .replace(/h[xX]{2}ps?:\/\//gi, function (m) { return m.toLowerCase().indexOf('s') > -1 ? 'https://' : 'http://'; })
      .replace(/h\[tt\]ps?:\/\//gi, 'http://')
      .replace(/\[:\]/g, ':').replace(/\[\/\]/g, '/')
      .replace(/(\w)\[@\](\w)/g, '$1@$2').replace(/\[at\]/gi, '@');
  }
  function extractIocs(text) {
    text = refang(text);
    var out = { hashes: {}, ips: {}, domains: {}, urls: {} };
    var add = function (o, v) { if (v) o[v] = true; };
    (text.match(/\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g) || [])
      .forEach(function (h) { add(out.hashes, h.toLowerCase()); });
    (text.match(/\bhttps?:\/\/[^\s"'<>)\]]+/gi) || [])
      .forEach(function (u) { add(out.urls, u.replace(/[.,;:)\]]+$/, '')); });
    (text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).forEach(function (ip) {
      if (ip.split('.').every(function (o) { return +o >= 0 && +o <= 255; })) add(out.ips, ip);
    });
    (text.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi) || []).forEach(function (d) {
      d = d.toLowerCase();
      if (/\.(exe|dll|sys|doc|docx|pdf|txt|png|jpg|jpeg|gif|bmp|svg|html?|xml|json|csv|zip|rar|7z|gz|tar|bin|dat|tmp|log|ini|cfg|msi|bat|ps1|vbs|jar|dmg|iso)$/.test(d)) return;
      add(out.domains, d);
    });
    return {
      hashes: Object.keys(out.hashes), ips: Object.keys(out.ips),
      domains: Object.keys(out.domains), urls: Object.keys(out.urls),
    };
  }
  function extractHints(text) {
    var hints = { signers: {}, asns: {}, registrars: {} };
    var lines = (text || '').split(/\r?\n/);
    var grab = function (re, bag) {
      lines.forEach(function (ln) { var m = ln.match(re); if (m && m[1]) { var v = m[1].trim().replace(/[)\].,;:]+$/, '').slice(0, 80); if (v) bag[v] = true; } });
    };
    grab(/(?:signed by|signer|signature subject|signing certificate|cn=)\s*[:=]?\s*"?([^",;]{3,80})"?/i, hints.signers);
    (text.match(/\bAS\s?(\d{2,6})\b/gi) || []).forEach(function (m) { hints.asns[m.replace(/\s/g, '').toUpperCase()] = true; });
    grab(/(?:as[-\s]?name|autonomous system)\s*[:=]?\s*"?([^",;]{2,80})"?/i, hints.asns);
    grab(/registrar\s*[:=]?\s*"?([^",;]{2,80})"?/i, hints.registrars);
    return { signers: Object.keys(hints.signers), asns: Object.keys(hints.asns), registrars: Object.keys(hints.registrars) };
  }

  /* ---- DOCX ---- */
  function extractDocx(buf, H) {
    return loadScript(CDN.mammoth).then(function () {
      H.log('mammoth loaded; extracting docx text…');
      return window.mammoth.extractRawText({ arrayBuffer: buf }).then(function (r) { return r.value || ''; });
    });
  }

  /* ---- PDF text + OCR fallback ---- */
  function ensurePdfjs() {
    if (pdfjsLib) return Promise.resolve();
    return loadScript(CDN.pdfjs).then(function () {
      pdfjsLib = window.pdfjsLib || window['pdfjs-dist/build/pdf'];
      if (!pdfjsLib) throw new Error('pdf.js did not initialize');
      try { pdfjsLib.GlobalWorkerOptions.workerSrc = CDN.pdfworker; } catch (e) {}
    });
  }
  function extractPdf(buf, H) {
    var textOut = '';
    var pages = [];
    return ensurePdfjs().then(function () {
      H.log('pdf.js loaded; reading pages…');
      return pdfjsLib.getDocument({ data: buf }).promise;
    }).then(function (pdf) {
      var n = pdf.numPages;
      H.log('pdf has ' + n + ' page(s). pass 1: text layer…');
      var chain = Promise.resolve();
      for (var i = 1; i <= n; i++) {
        (function (pageNum) {
          chain = chain.then(function () {
            return pdf.getPage(pageNum).then(function (page) {
              return page.getTextContent().then(function (tc) {
                var pageText = tc.items.map(function (it) { return it.str; }).join(' ');
                textOut += '\n' + pageText;
                H.prog((pageNum / n) * 45);
                pages.push({ page: page, hadText: pageText.trim().length > 8 });
              });
            });
          });
        })(i);
      }
      return chain.then(function () { return { text: textOut, pages: pages, n: n }; });
    });
  }
  function ocrPdfPages(info, H) {
    var need = info.pages.filter(function (p) { return !p.hadText; });
    if (!need.length) { H.log('all pages had selectable text — OCR not needed.', 'ok'); return Promise.resolve(''); }
    H.log('pass 2: ' + need.length + ' page(s) need OCR. loading Tesseract…');
    return loadScript(CDN.tesseract).then(function () {
      var Tesseract = window.Tesseract;
      if (!Tesseract) throw new Error('Tesseract.js did not initialize');
      var cv = document.getElementById('reportCanvas');
      var ctx = cv.getContext('2d');
      var ocr = '', idx = 0;
      function next() {
        if (idx >= need.length) return Promise.resolve(ocr);
        var info2 = need[idx++];
        var vp = info2.page.getViewport({ scale: 2.0 });
        cv.width = vp.width; cv.height = vp.height;
        return info2.page.render({ canvasContext: ctx, viewport: vp }).promise.then(function () {
          H.log('OCR page ' + idx + '/' + need.length + '…');
          return Tesseract.recognize(cv, 'eng', {
            logger: function (m) { if (m.status === 'recognizing text') H.prog(45 + (idx - 1 + m.progress) / need.length * 50); }
          });
        }).then(function (r) { ocr += '\n' + ((r.data && r.data.text) || ''); return next(); });
      }
      return next();
    });
  }

  function run(file, H) {
    H = H || {}; var noop = function () {};
    H.log = H.log || noop; H.status = H.status || noop; H.prog = H.prog || noop; H.counts = H.counts || noop;
    var name = file.name, lower = (name || '').toLowerCase();
    return file.arrayBuffer().then(function (buf) {
      var pipeline;
      if (lower.endsWith('.docx')) {
        H.status('extracting text from .docx…');
        pipeline = extractDocx(buf, H).then(function (t) { H.prog(60); return { text: t, basis: 'docx text' }; });
      } else if (lower.endsWith('.pdf')) {
        H.status('reading PDF…');
        pipeline = extractPdf(buf, H).then(function (info) {
          return ocrPdfPages(info, H).then(function (ocr) {
            return { text: info.text + '\n' + ocr, basis: ocr ? 'pdf text + OCR' : 'pdf text' };
          });
        });
      } else {
        return Promise.reject(new Error('unsupported file type (only .pdf and .docx)'));
      }
      return pipeline.then(function (r) {
        H.prog(96); H.status('parsing indicators…');
        var io = extractIocs(r.text), hints = extractHints(r.text);
        H.counts(io, hints, r.basis);
        H.prog(100);
        return {
          reportName: name, basis: r.basis,
          hashes: io.hashes, ips: io.ips, domains: io.domains, urls: io.urls,
          signers: hints.signers, asns: hints.asns, registrars: hints.registrars,
          textLength: (r.text || '').length,
        };
      });
    });
  }

  // Remove everything this engine pulled in: terminate Tesseract, drop injected
  // <script>s, and null the library globals so they can be GC'd.
  function teardown() {
    try { if (window.Tesseract && window.Tesseract.terminate) window.Tesseract.terminate(); } catch (e) {}
    injected.forEach(function (s) { try { s.remove(); } catch (e) {} });
    injected = [];
    pdfjsLib = null;
    try { delete window.mammoth; } catch (e) { window.mammoth = undefined; }
    try { delete window.pdfjsLib; } catch (e) { window.pdfjsLib = undefined; }
    try { delete window.Tesseract; } catch (e) { window.Tesseract = undefined; }
  }

  window.IoCHubReport = { run: run, teardown: teardown };
})();
