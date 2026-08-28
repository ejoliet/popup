/* popup — FITS / ASDF header + HDU viewer.
 *
 * Header display only: no image rendering (explicit non-goal in the README).
 * Everything is read with HTTP Range requests against /raw/<file>, so opening a
 * 40 GB cube costs a few tens of KB.
 *
 * Public API (used by shell.html):
 *   window.popupFits.render(rootElement, rawUrl) -> Promise<void>
 */
"use strict";
(function () {
  const BLOCK = 2880;          // FITS logical record
  const CARD = 80;             // characters per card
  const CHUNK = BLOCK * 8;     // bytes fetched per range request while scanning a header
  const MAX_HDUS = 128;
  const MAX_HEADER_BLOCKS = 256;
  const dec = new TextDecoder("latin1");

  async function getRange(url, start, len) {
    const r = await fetch(url, {
      headers: { Range: "bytes=" + start + "-" + (start + len - 1) },
      cache: "no-store",
    });
    if (r.status === 416) return { text: "", total: null };
    if (!r.ok) throw new Error("HTTP " + r.status + " reading " + url);
    const cr = r.headers.get("Content-Range");
    let total = null;
    if (cr && cr.indexOf("/") >= 0) {
      const n = parseInt(cr.split("/")[1], 10);
      if (!isNaN(n)) total = n;
    }
    let bytes = new Uint8Array(await r.arrayBuffer());
    if (r.status !== 206) {
      // Server ignored Range and sent the whole entity: slice locally so the
      // caller's offset arithmetic still holds.
      if (total == null) total = bytes.length;
      bytes = bytes.subarray(Math.min(start, bytes.length), Math.min(start + len, bytes.length));
    }
    return { text: dec.decode(bytes), total: total };
  }

  // ---- card parsing -------------------------------------------------------
  // "KEY     = value / comment", strings single-quoted with '' as an escaped quote.
  function parseCard(card) {
    const key = card.slice(0, 8).trim();
    if (!key) return null;
    if (key === "END") return { key: "END", value: "", comment: "" };
    if (key === "COMMENT" || key === "HISTORY" || key === "CONTINUE" || card.slice(8, 10) !== "= ") {
      return { key: key, value: "", comment: card.slice(8).trim() };
    }
    const s = card.slice(10);
    const q = s.indexOf("'");
    let value, rest;
    if (q >= 0 && s.slice(0, q).trim() === "") {
      let i = q + 1, out = "";
      while (i < s.length) {
        if (s[i] === "'") {
          if (s[i + 1] === "'") { out += "'"; i += 2; continue; }
          i++; break;
        }
        out += s[i++];
      }
      value = out.replace(/\s+$/, "");   // FITS pads strings with blanks
      rest = s.slice(i);
    } else {
      const slash = s.indexOf("/");
      value = (slash < 0 ? s : s.slice(0, slash)).trim();
      rest = slash < 0 ? "" : s.slice(slash);
    }
    const slash = rest.indexOf("/");
    return { key: key, value: value, comment: slash < 0 ? "" : rest.slice(slash + 1).trim() };
  }

  function typed(v) {
    if (v === "T") return true;
    if (v === "F") return false;
    if (v === "") return null;
    const n = Number(String(v).replace(/[DdEe]([+-]?\d+)$/, "e$1"));
    return isNaN(n) ? v : n;
  }

  function toMap(cards) {
    const m = Object.create(null);
    for (const c of cards) if (!(c.key in m) && c.key !== "COMMENT" && c.key !== "HISTORY") m[c.key] = typed(c.value);
    return m;
  }

  // Data unit size per the FITS standard, rounded up to whole 2880-byte blocks.
  function dataBytes(h) {
    const naxis = Number(h.NAXIS) || 0;
    if (!naxis) return 0;
    let n = 1;
    for (let i = 1; i <= naxis; i++) n *= Number(h["NAXIS" + i]) || 0;
    const width = Math.abs(Number(h.BITPIX) || 0) / 8;
    const gcount = h.GCOUNT == null ? 1 : Number(h.GCOUNT);
    const pcount = h.PCOUNT == null ? 0 : Number(h.PCOUNT);
    const size = width * gcount * (pcount + n);
    return Math.ceil(size / BLOCK) * BLOCK;
  }

  // ---- HDU walking --------------------------------------------------------
  async function readHeader(url, offset) {
    let buf = "", total = null, cards = [], endAt = -1;
    while (endAt < 0) {
      if (buf.length / BLOCK > MAX_HEADER_BLOCKS) throw new Error("no END card within " + MAX_HEADER_BLOCKS + " blocks");
      const got = await getRange(url, offset + buf.length, CHUNK);
      if (got.total != null) total = got.total;
      if (!got.text.length) return null;
      const from = buf.length;
      buf += got.text;
      for (let i = from - (from % CARD); i + CARD <= buf.length; i += CARD) {
        const c = parseCard(buf.slice(i, i + CARD));
        if (!c) continue;
        if (c.key === "END") { endAt = i + CARD; break; }
        cards.push(c);
      }
      if (got.text.length < CHUNK) break;   // hit EOF
    }
    if (endAt < 0) return null;
    return { cards: cards, headerBytes: Math.ceil(endAt / BLOCK) * BLOCK, total: total };
  }

  async function readHDUs(url) {
    const hdus = [];
    let offset = 0, total = null;
    while (hdus.length < MAX_HDUS) {
      const h = await readHeader(url, offset);
      if (!h) break;
      if (h.total != null) total = h.total;
      const map = toMap(h.cards);
      if (!hdus.length && !("SIMPLE" in map)) throw new Error("not a FITS file (no SIMPLE card)");
      const data = dataBytes(map);
      hdus.push({ index: hdus.length, offset: offset, cards: h.cards, map: map, dataBytes: data });
      offset += h.headerBytes + data;
      if (total != null && offset >= total) break;
    }
    return { hdus: hdus, total: total };
  }

  // ---- ASDF ---------------------------------------------------------------
  // ASDF files start with "#ASDF <version>" and a YAML document terminated by "..." on its own line.
  async function readAsdf(url) {
    let buf = "";
    for (let i = 0; i < 8; i++) {
      const got = await getRange(url, buf.length, CHUNK * 4);
      if (!got.text.length) break;
      buf += got.text;
      const end = buf.search(/^\.\.\.\s*$/m);
      if (end >= 0) return buf.slice(0, end).replace(/\s+$/, "");
      if (got.text.length < CHUNK * 4) break;
    }
    return buf;
  }

  // ---- rendering ----------------------------------------------------------
  function el(tag, attrs, text) {
    const e = document.createElement(tag);
    if (attrs) for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = text;
    return e;
  }

  function hduTitle(hdu) {
    const m = hdu.map;
    const parts = ["HDU " + hdu.index];
    parts.push(hdu.index === 0 ? String(m.XTENSION || "PRIMARY") : String(m.XTENSION || "IMAGE"));
    if (m.EXTNAME) parts.push(String(m.EXTNAME));
    const naxis = Number(m.NAXIS) || 0;
    if (naxis) {
      const dims = [];
      for (let i = 1; i <= naxis; i++) dims.push(m["NAXIS" + i]);
      parts.push("[" + dims.join(" x ") + "]");
    } else parts.push("no data");
    if (m.BITPIX != null) parts.push("BITPIX " + m.BITPIX);
    parts.push("data " + hdu.dataBytes + " B @ " + hdu.offset);
    return parts.join(" · ");
  }

  function renderHDU(hdu) {
    const box = el("section", { class: "fits-hdu" });
    box.appendChild(el("h3", null, hduTitle(hdu)));
    const t = el("table", { class: "grid" });
    const head = el("tr");
    ["keyword", "value", "comment"].forEach((h) => head.appendChild(el("th", null, h)));
    t.appendChild(el("thead")).appendChild(head);
    const body = el("tbody");
    hdu.cards.forEach((c) => {
      const tr = el("tr");
      tr.appendChild(el("td", null, c.key));
      tr.appendChild(el("td", null, c.value));
      tr.appendChild(el("td", null, c.comment));
      body.appendChild(tr);
    });
    t.appendChild(body);
    const wrap = el("div", { class: "scroll" });
    wrap.appendChild(t);
    box.appendChild(wrap);
    return box;
  }

  async function render(root, url) {
    root.appendChild(el("div", { class: "msg" }, "reading header…"));
    try {
      const head = await getRange(url, 0, BLOCK);
      root.innerHTML = "";
      if (head.text.slice(0, 5) === "#ASDF") {
        root.appendChild(el("h3", null, "ASDF header"));
        root.appendChild(el("pre", { class: "plain" }, await readAsdf(url)));
        return;
      }
      const out = await readHDUs(url);
      root.appendChild(el("div", { class: "msg" },
        out.hdus.length + " HDU" + (out.hdus.length === 1 ? "" : "s") +
        (out.total != null ? " · " + out.total + " bytes total" : "")));
      out.hdus.forEach((h) => root.appendChild(renderHDU(h)));
    } catch (e) {
      root.innerHTML = "";
      root.appendChild(el("div", { class: "err" }, String((e && e.message) || e)));
    }
  }

  window.popupFits = { render: render, parseCard: parseCard, dataBytes: dataBytes, readHDUs: readHDUs };
})();
