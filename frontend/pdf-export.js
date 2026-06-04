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
 * IoCHub PDF export — report renderer (jsPDF).
 *
 * Loaded on demand by app.js (exportGraphPdf). Depends only on:
 *   - window.jspdf   (vendor/jspdf.umd.min.js)
 *
 * Styling matches the IoCHub interface: a monospace face (jsPDF's built-in
 * Courier, mirroring the app's monospace UI) and the user's chosen accent
 * colour. No external fonts or images are embedded.
 *
 * Layout:
 *   page 1  — header + the graph image (PNG from Cytoscape)
 *   page 2  — overview (counts)
 *   then    — one section per entity: the same indicator info as the MISP export
 *             plus every connection it made
 *   then    — a full connections listing
 *
 * Exposes window.IoCHubPdf.build({ model, graphPng, accent, filename }).
 */
(function () {
  'use strict';

  var INK = '#222222';
  var MUTE = '#6b6b6b';
  var LINE = '#dcdcdc';
  var MAL = '#b00020';            // muted red for "malicious", theme-independent

  // hex -> [r,g,b]
  function rgb(hex) {
    var h = String(hex || '').replace('#', '');
    if (h.length === 3) h = h.split('').map(function (c) { return c + c; }).join('');
    return [parseInt(h.slice(0, 2), 16) || 0, parseInt(h.slice(2, 4), 16) || 0, parseInt(h.slice(4, 6), 16) || 0];
  }

  function build(opts) {
    var model = opts.model;
    var graphPng = opts.graphPng;
    var accent = opts.accent || '#c8702a';
    var filename = opts.filename || 'iochub-report.pdf';

    var jsPDF = window.jspdf && window.jspdf.jsPDF;
    if (!jsPDF) throw new Error('jsPDF not available');

    var doc = new jsPDF({ unit: 'pt', format: 'a4', compress: true });
    // The IoCHub UI is monospace; Courier is jsPDF's built-in monospace face, so
    // no font needs to be embedded (keeps the export dependency-free).
    var FONT = 'courier';

    var PW = doc.internal.pageSize.getWidth();
    var PH = doc.internal.pageSize.getHeight();
    var M = 40;
    var contentW = PW - M * 2;
    var y = M;

    function setFill(hex) { var c = rgb(hex); doc.setFillColor(c[0], c[1], c[2]); }
    function setText(hex) { var c = rgb(hex); doc.setTextColor(c[0], c[1], c[2]); }
    function setDraw(hex) { var c = rgb(hex); doc.setDrawColor(c[0], c[1], c[2]); }
    function font(style, size) { doc.setFont(FONT, style); doc.setFontSize(size); }

    function pageChrome() {
      // top rule in the user's accent
      setDraw(accent); doc.setLineWidth(2);
      doc.line(M, 28, PW - M, 28);
      // footer hairline + text
      setDraw(LINE); doc.setLineWidth(0.6); doc.line(M, PH - 22, PW - M, PH - 22);
      font('normal', 7); setText(MUTE);
      doc.text('IoCHub — indicator-of-compromise report', M, PH - 12);
    }

    var _pageNum = 0;
    function footerPageNum() {
      font('normal', 7); setText(MUTE);
      doc.text('page ' + (_pageNum + 1), PW - M, PH - 12, { align: 'right' });
    }
    function ensure(space) { if (y + space > PH - 34) newPage(); }
    function newPage() { doc.addPage(); _pageNum++; pageChrome(); footerPageNum(); y = M + 8; }

    function para(text, style, size, color, indent) {
      font(style, size); setText(color || INK);
      var x = M + (indent || 0);
      var lines = doc.splitTextToSize(String(text == null ? '' : text), contentW - (indent || 0));
      for (var i = 0; i < lines.length; i++) { ensure(size + 4); doc.text(lines[i], x, y); y += size + 4; }
      return lines.length;
    }

    // a small "kind" pill in the user's accent
    function kindPill(kind, x, top) {
      font('bold', 8);
      var label = String(kind || '').toUpperCase();
      var w = doc.getTextWidth(label) + 12;
      setFill(accent); doc.roundedRect(x, top - 9, w, 13, 2, 2, 'F');
      setText('#FFFFFF'); doc.text(label, x + 6, top);
      return w;
    }

    // ============================ PAGE 1 — HEADER + GRAPH =================
    pageChrome(); footerPageNum();
    font('bold', 24); setText(INK);
    doc.text('IoCHub', M, M + 16);
    font('normal', 12); setText(accent);
    doc.text('Indicator-of-Compromise report', M, M + 34);
    font('normal', 9); setText(MUTE);
    var gen = (model.generated || '').replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
    doc.text('Generated ' + gen, M, M + 50);
    setDraw(accent); doc.setLineWidth(1.2); doc.line(M, M + 58, PW - M, M + 58);

    var imgTop = M + 72;
    var availW = contentW;
    var availH = (PH - 34) - imgTop;
    if (graphPng) {
      try {
        var props = doc.getImageProperties(graphPng);
        var ar = props.width / props.height;
        var w = availW, h = w / ar;
        if (h > availH) { h = availH; w = h * ar; }
        var ix = M + (availW - w) / 2;
        doc.addImage(graphPng, 'PNG', ix, imgTop, w, h, undefined, 'FAST');
      } catch (e) {
        font('normal', 10); setText(MUTE);
        doc.text('(graph image unavailable)', M, imgTop + 20);
      }
    }

    // ============================ PAGE 2 — OVERVIEW ======================
    newPage();
    font('bold', 16); setText(INK); doc.text('Overview', M, y); y += 22;
    var c = model.counts || {};
    var rows = [
      ['Entities', c.entities], ['Files', c.files], ['Domains', c.domains],
      ['IP addresses', c.ips], ['URLs', c.urls], ['Connections', c.connections],
    ];
    for (var r = 0; r < rows.length; r++) {
      ensure(20);
      font('normal', 11); setText(MUTE); doc.text(String(rows[r][0]), M, y);
      font('bold', 11); setText(INK); doc.text(String(rows[r][1] == null ? 0 : rows[r][1]), M + 160, y);
      y += 18;
    }
    y += 6; setDraw(LINE); doc.setLineWidth(0.6); doc.line(M, y, PW - M, y); y += 16;

    // ============================ ENTITY SECTIONS ========================
    font('bold', 16); setText(INK); ensure(26); doc.text('Entities', M, y); y += 22;

    (model.entityRecords || []).forEach(function (rec) {
      ensure(60);
      var px = kindPill(rec.kind, M, y);
      font('bold', 11); setText(INK);
      var headLines = doc.splitTextToSize(rec.value, contentW - px - 8);
      doc.text(headLines[0], M + px + 8, y); y += 15;
      if (headLines.length > 1) para(headLines.slice(1).join(' '), 'bold', 11, INK, 0);
      if (rec.name) para('name: ' + rec.name, 'normal', 9, MUTE, 0);
      var status = [rec.malicious ? 'malicious' : 'not flagged'];
      if (rec.enriched) status.push('enriched');
      para(status.join(' \u00b7 '), 'normal', 8, rec.malicious ? MAL : MUTE, 0);

      if (rec.indicators && rec.indicators.length) {
        para('Indicators', 'bold', 9, INK, 0);
        rec.indicators.forEach(function (ind) {
          ensure(13); font('normal', 9); setText(MUTE);
          doc.text(ind.label, M + 8, y); setText(INK);
          var vlines = doc.splitTextToSize(ind.value, contentW - 8 - 110);
          doc.text(vlines[0], M + 110, y); y += 12;
          for (var i = 1; i < vlines.length; i++) { ensure(12); doc.text(vlines[i], M + 110, y); y += 12; }
        });
      }
      if (rec.connections && rec.connections.length) {
        para('Connections (' + rec.connections.length + ')', 'bold', 9, INK, 0);
        rec.connections.forEach(function (cn) {
          ensure(12); font('normal', 9);
          setText(accent); doc.text('->', M + 8, y);
          setText(MUTE);
          var rel = cn.relation ? (cn.relation + '  ') : '';
          doc.text(rel, M + 22, y);
          var relW = doc.getTextWidth(rel);
          setText(INK);
          var line = (cn.toKind && cn.toKind !== '?' ? '[' + cn.toKind + '] ' : '') + cn.to;
          var cl = doc.splitTextToSize(line, contentW - 22 - relW - 8);
          doc.text(cl[0], M + 22 + relW, y); y += 12;
          for (var i = 1; i < cl.length; i++) { ensure(12); doc.text(cl[i], M + 30, y); y += 12; }
        });
      }
      y += 6; setDraw(LINE); doc.setLineWidth(0.5); ensure(8); doc.line(M, y, PW - M, y); y += 14;
    });

    // ============================ CONNECTIONS LISTING ====================
    var conns = model.connList || [];
    if (conns.length) {
      ensure(40);
      font('bold', 16); setText(INK); doc.text('All connections', M, y); y += 22;
      conns.forEach(function (cn) {
        ensure(13); font('normal', 9); setText(INK);
        var left = (cn.fromKind && cn.fromKind !== '?' ? '[' + cn.fromKind + '] ' : '') + cn.from;
        var right = (cn.toKind && cn.toKind !== '?' ? '[' + cn.toKind + '] ' : '') + cn.to;
        var full = left + '   --' + (cn.relation ? ' ' + cn.relation + ' ' : ' ') + '->   ' + right;
        var ls = doc.splitTextToSize(full, contentW);
        doc.text(ls[0], M, y); y += 12;
        for (var i = 1; i < ls.length; i++) { ensure(12); doc.text(ls[i], M + 12, y); y += 12; }
      });
    }

    doc.save(filename);
  }

  window.IoCHubPdf = { build: build };
})();
