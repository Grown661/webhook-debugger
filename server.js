'use strict';

/**
 * webhook-debugger — Webhook-Empfaenger & Debugger (wie requestbin).
 * Dependency-frei: nur Node-Builtins. Persistenz: JSON-Datei unter data/.
 */

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const fssync = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');
const dns = require('node:dns/promises');
const net = require('node:net');

const PORT = Number(process.env.PORT) || 8216;
// Opt-in-SSRF-Schutz fuer Forwards: Forward an localhost/LAN ist bei einem
// Debug-Tool oft gewollt, darum default AUS. Aktivieren mit SSRF_PROTECT=1.
const SSRF_PROTECT = process.env.SSRF_PROTECT === '1';
const MAX_REQUESTS_PER_BIN = 50; // Ringpuffer
const MAX_BODY_BYTES = 256 * 1024; // 256 KB pro Request-Body
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'bins.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// ---------------------------------------------------------------------------
// Datenhaltung
// ---------------------------------------------------------------------------

// bins: { [binId]: { id, createdAt, forwardUrl: string|null, requests: [...] } }
let bins = {};
let writeQueue = Promise.resolve();

function newBinId() {
  return crypto.randomBytes(5).toString('hex');
}

async function loadStore() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    bins = JSON.parse(await fs.readFile(DATA_FILE, 'utf8'));
    if (typeof bins !== 'object' || bins === null || Array.isArray(bins)) throw new Error('bad store');
  } catch {
    bins = {};
  }
}

function persist() {
  writeQueue = writeQueue.then(() =>
    fs.writeFile(DATA_FILE, JSON.stringify(bins, null, 2), 'utf8')
  ).catch((e) => console.error('persist:', e.message));
  return writeQueue;
}

// ---------------------------------------------------------------------------
// Helfer
// ---------------------------------------------------------------------------

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function readBody(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    let truncated = false;
    req.on('data', (c) => {
      if (size >= maxBytes) {
        truncated = true;
        return; // Rest verwerfen, aber Request nicht abbrechen (Webhook soll 200 kriegen)
      }
      size += c.length;
      chunks.push(c);
    });
    req.on('end', () => resolve({ body: Buffer.concat(chunks).toString('utf8'), truncated }));
    req.on('error', () => resolve({ body: Buffer.concat(chunks).toString('utf8'), truncated: true }));
  });
}

// ---------- SSRF-Schutz (dependency-frei, net.BlockList) ----------

// net.BlockList statt manueller Range-Pruefung: BlockList normalisiert auch
// IPv4-mapped IPv6 in HEX-Form (::ffff:7f00:1) und matcht sie gegen die
// IPv4-Subnets — die manuelle Pruefung erkannte nur die Punktform.
const PRIVATE_BLOCKLIST = new net.BlockList();
PRIVATE_BLOCKLIST.addSubnet('0.0.0.0', 8, 'ipv4');      // "this network"
PRIVATE_BLOCKLIST.addSubnet('10.0.0.0', 8, 'ipv4');     // privat
PRIVATE_BLOCKLIST.addSubnet('127.0.0.0', 8, 'ipv4');    // loopback
PRIVATE_BLOCKLIST.addSubnet('169.254.0.0', 16, 'ipv4'); // link-local
PRIVATE_BLOCKLIST.addSubnet('172.16.0.0', 12, 'ipv4');  // privat
PRIVATE_BLOCKLIST.addSubnet('192.168.0.0', 16, 'ipv4'); // privat
PRIVATE_BLOCKLIST.addAddress('::', 'ipv6');             // unspecified
PRIVATE_BLOCKLIST.addSubnet('::1', 128, 'ipv6');        // loopback
PRIVATE_BLOCKLIST.addSubnet('fc00::', 7, 'ipv6');       // ULA
PRIVATE_BLOCKLIST.addSubnet('fe80::', 10, 'ipv6');      // link-local

function isPrivateOrReservedIp(ip) {
  const family = net.isIP(ip);
  if (family === 0) return true; // unbekanntes Format -> sicherheitshalber blocken
  return PRIVATE_BLOCKLIST.check(ip, family === 6 ? 'ipv6' : 'ipv4');
}

// Wirft, wenn die URL nicht auf eine oeffentliche IP zeigt.
// Gibt die geprueften Daten zurueck, inkl. einer lookup-Funktion, die genau die
// geprueften IP PINNT — der eigentliche Request darf kein zweites DNS-Lookup
// machen (DNS-Rebinding/TOCTOU: kurze TTL koennte beim 2. Lookup privat aufloesen).
async function assertPublicUrl(urlString) {
  let u;
  try { u = new URL(urlString); } catch { throw new Error('ungueltige URL'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error('nur http/https erlaubt');
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (host.toLowerCase() === 'localhost') throw new Error('localhost ist geblockt');
  let addrs;
  if (net.isIP(host)) {
    addrs = [{ address: host, family: net.isIP(host) }];
  } else {
    try { addrs = await dns.lookup(host, { all: true }); }
    catch { throw new Error(`DNS-Aufloesung fehlgeschlagen: ${host}`); }
  }
  if (!addrs.length) throw new Error(`DNS-Aufloesung leer: ${host}`);
  for (const { address } of addrs) {
    if (isPrivateOrReservedIp(address)) {
      throw new Error(`private/reservierte Ziel-IP geblockt: ${host} -> ${address}`);
    }
  }
  const pinned = addrs[0];
  const family = pinned.family || net.isIP(pinned.address);
  const lookup = (hostname, options, cb) => {
    if (typeof options === 'function') { cb = options; options = {}; }
    if (options && options.all) cb(null, [{ address: pinned.address, family }]);
    else cb(null, pinned.address, family);
  };
  return { url: u, address: pinned.address, family, lookup };
}

async function forwardRequest(binReq, forwardUrl) {
  // Fire-and-forget-Weiterleitung; Ergebnis wird am gespeicherten Request notiert.
  let pinnedLookup = null;
  if (SSRF_PROTECT) {
    // Geprüfte IP pinnen: der Request unten macht kein zweites DNS-Lookup
    // (DNS-Rebinding/TOCTOU). Ohne SSRF_PROTECT bleibt alles beim Default.
    try { pinnedLookup = (await assertPublicUrl(forwardUrl)).lookup; }
    catch (e) { return { ok: false, error: `SSRF-Schutz: ${e.message}` }; }
  }
  return new Promise((resolve) => {
    let target;
    try {
      target = new URL(forwardUrl);
    } catch {
      resolve({ ok: false, error: 'invalid forwardUrl' });
      return;
    }
    if (target.protocol !== 'http:' && target.protocol !== 'https:') {
      resolve({ ok: false, error: 'only http/https forward supported' });
      return;
    }
    const mod = target.protocol === 'https:' ? require('node:https') : http;
    const headers = { ...binReq.headers };
    delete headers.host;
    delete headers['content-length'];
    const fwd = mod.request(
      target,
      { method: binReq.method, headers, timeout: 5000, ...(pinnedLookup ? { lookup: pinnedLookup } : {}) },
      (fres) => {
        fres.resume();
        resolve({ ok: true, status: fres.statusCode });
      }
    );
    fwd.on('timeout', () => {
      fwd.destroy();
      resolve({ ok: false, error: 'forward timeout (5s)' });
    });
    fwd.on('error', (e) => resolve({ ok: false, error: e.message }));
    if (binReq.body) fwd.write(binReq.body);
    fwd.end();
  });
}

// ---------------------------------------------------------------------------
// HTTP-Server
// ---------------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname.replace(/\/+$/, '') || '/';

  try {
    // ---- Webhook-Empfang: JEDE Methode an /hook/:binId -------------------
    const hookMatch = pathname.match(/^\/hook\/([a-zA-Z0-9]+)$/);
    if (hookMatch) {
      const binId = hookMatch[1];
      // Nur echte eigene Keys — sonst liefert bins['constructor'] die Prototype-Funktion
      const bin = Object.hasOwn(bins, binId) ? bins[binId] : null;
      if (!bin) {
        sendJson(res, 404, { error: 'bin not found', hint: 'Bin zuerst im UI erstellen' });
        return;
      }

      const { body, truncated } = await readBody(req);
      const entry = {
        id: crypto.randomBytes(4).toString('hex'),
        method: req.method,
        headers: req.headers,
        query: Object.fromEntries(url.searchParams),
        body,
        bodyTruncated: truncated,
        receivedAt: new Date().toISOString(),
        ip: req.socket.remoteAddress || 'unknown',
        forward: null,
      };

      if (bin.forwardUrl) {
        entry.forward = await forwardRequest(
          { method: req.method, headers: req.headers, body },
          bin.forwardUrl
        );
      }

      bin.requests.push(entry);
      if (bin.requests.length > MAX_REQUESTS_PER_BIN) {
        bin.requests.splice(0, bin.requests.length - MAX_REQUESTS_PER_BIN);
      }
      await persist();

      sendJson(res, 200, { ok: true, bin: binId, stored: entry.id });
      return;
    }

    // ---- API --------------------------------------------------------------
    if (req.method === 'POST' && pathname === '/api/bins') {
      let forwardUrl = null;
      const { body } = await readBody(req);
      if (body) {
        // Body ist optional; wenn vorhanden, muss er ein JSON-Objekt sein
        // (JSON.parse('null') liefert null ohne Fehler -> sonst 500 statt 400)
        let parsed;
        try {
          parsed = JSON.parse(body);
        } catch {
          sendJson(res, 400, { error: 'invalid body' });
          return;
        }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          sendJson(res, 400, { error: 'invalid body' });
          return;
        }
        if (parsed.forwardUrl && typeof parsed.forwardUrl === 'string') {
          forwardUrl = parsed.forwardUrl;
        }
      }
      const id = newBinId();
      bins[id] = { id, createdAt: new Date().toISOString(), forwardUrl, requests: [] };
      await persist();
      sendJson(res, 201, { id, forwardUrl, hookUrl: `/hook/${id}` });
      return;
    }

    const binApiMatch = pathname.match(/^\/api\/bins\/([a-zA-Z0-9]+)(\/requests)?$/);
    if (binApiMatch) {
      // Nur echte eigene Keys — sonst liefert bins['constructor'] die Prototype-Funktion
      const bin = Object.hasOwn(bins, binApiMatch[1]) ? bins[binApiMatch[1]] : null;
      if (!bin) return sendJson(res, 404, { error: 'bin not found' });

      if (req.method === 'GET' && binApiMatch[2]) {
        // /api/bins/:id/requests — neueste zuerst
        const limit = Math.min(Number(url.searchParams.get('limit')) || MAX_REQUESTS_PER_BIN, MAX_REQUESTS_PER_BIN);
        sendJson(res, 200, {
          bin: bin.id,
          forwardUrl: bin.forwardUrl,
          count: bin.requests.length,
          requests: bin.requests.slice(-limit).reverse(),
        });
        return;
      }

      if (req.method === 'GET') {
        sendJson(res, 200, { id: bin.id, createdAt: bin.createdAt, forwardUrl: bin.forwardUrl, requestCount: bin.requests.length });
        return;
      }

      if (req.method === 'PUT') {
        const { body } = await readBody(req);
        let parsed;
        try {
          parsed = JSON.parse(body || '{}');
        } catch {
          sendJson(res, 400, { error: 'invalid JSON body' });
          return;
        }
        // JSON.parse('null') liefert null ohne Fehler -> ohne Check gaebe es 500 statt 400
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          sendJson(res, 400, { error: 'invalid body' });
          return;
        }
        bin.forwardUrl = typeof parsed.forwardUrl === 'string' && parsed.forwardUrl ? parsed.forwardUrl : null;
        await persist();
        sendJson(res, 200, { id: bin.id, forwardUrl: bin.forwardUrl });
        return;
      }

      if (req.method === 'DELETE') {
        delete bins[bin.id];
        await persist();
        res.writeHead(204);
        res.end();
        return;
      }

      sendJson(res, 405, { error: 'method not allowed' });
      return;
    }

    // ---- Web-UI -----------------------------------------------------------
    if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
      const html = fssync.readFileSync(path.join(PUBLIC_DIR, 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    sendJson(res, 404, { error: 'not found' });
  } catch (err) {
    console.error(err);
    sendJson(res, 500, { error: 'internal server error' });
  }
});

loadStore().then(() => {
  server.listen(PORT, () => {
    console.log(`webhook-debugger laeuft auf http://localhost:${PORT} (${Object.keys(bins).length} Bins)`);
  });
});
