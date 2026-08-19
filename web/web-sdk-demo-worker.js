// web-sdk-demo-worker.js — full @telezig/web storage loop.
//
// Loads BOTH wasm modules in one worker:
//   tz.wasm    — MTProto engine (unified Session, QR login, update handling)
//   tz-db.wasm — SQLite on OPFS (message store)
// and bridges them: every incoming message from the MTProto side is written
// into the OPFS sqlite store. This is the storage path the future @telezig/sdk
// will expose: engine -> persistence, all inside one worker.

let postLog = () => {};
let wasmDb = null, dbMemory = null, db = -1; // tz-db.wasm (store)
let mtp = null, mtpMemory = null;             // tz.wasm (MTProto)

// ---------- OPFS sqlite backend (same VFS glue as store-demo) ----------

class OpfsBackend {
  constructor(root) {
    this.root = root;
    this.handles = new Map();
    this.fds = new Map();
    this.deleted = new Set();
    this.nextFd = 1;
  }
  async preload(name, create) {
    const t = name.replace(/^\.\//, '');
    if (this.deleted.has(t)) {
      this.deleted.delete(t);
      try { const h = await this.root.getFileHandle(t, { create: true }); const s = await h.createSyncAccessHandle(); s.truncate(0); s.close(); } catch (e) {}
    }
    let fh;
    try { fh = await this.root.getFileHandle(t, { create }); } catch (e) { return false; }
    let sync;
    try { sync = await fh.createSyncAccessHandle(); } catch (e) { return false; }
    this.handles.set(t, { sync });
    return true;
  }
  open(name, create) {
    const t = name.replace(/^\.\//, '');
    const e = this.handles.get(t);
    if (!e) return -1;
    if (this.deleted.has(t)) {
      if (!create) return -1;
      this.deleted.delete(t);
      try { e.sync.truncate(0); } catch (e2) { return -1; }
    }
    const fd = this.nextFd++;
    this.fds.set(fd, t);
    return fd;
  }
  read(fd, off, dst) { const e = this.handles.get(this.fds.get(fd)); if (!e) return -1; try { return e.sync.read(dst, { at: Number(off) }); } catch (x) { return -1; } }
  write(fd, off, src) { const e = this.handles.get(this.fds.get(fd)); if (!e) return -1; try { return e.sync.write(src, { at: Number(off) }); } catch (x) { return -1; } }
  truncate(fd, size) { const e = this.handles.get(this.fds.get(fd)); if (!e) return -1; try { e.sync.truncate(Number(size)); return 0; } catch (x) { return -1; } }
  size(fd) { const e = this.handles.get(this.fds.get(fd)); if (!e) return -1; try { return e.sync.getSize(); } catch (x) { return -1; } }
  flush(fd) { const e = this.handles.get(this.fds.get(fd)); if (!e) return -1; try { e.sync.flush(); return 0; } catch (x) { return -1; } }
  close(fd) { this.fds.delete(fd); }
  delete(name) {
    const t = name.replace(/^\.\//, '');
    this.deleted.add(t);
    for (const [fd, nm] of this.fds) if (nm === t) this.fds.delete(fd);
    const e = this.handles.get(t);
    if (e) { try { e.sync.truncate(0); e.sync.flush(); } catch (x) {} }
    (async () => { try { await this.root.removeEntry(t); this.deleted.delete(t); } catch (x) { setTimeout(() => this.deleted.delete(t), 50); } })();
    return 0;
  }
  access(name) {
    const t = name.replace(/^\.\//, '');
    if (this.deleted.has(t)) return 0;
    if (t.endsWith('-journal')) return 0;
    return this.handles.has(t) ? 1 : 0;
  }
}

// ---------- store helpers (tz-db.wasm) ----------

function dbStr(s) {
  const b = new TextEncoder().encode(s);
  const p = wasmDb.tzdb_alloc(b.length);
  new Uint8Array(dbMemory.buffer, p, b.length).set(b);
  return [p, b.length];
}
function dbExec(sql) {
  const [p, l] = dbStr(sql);
  const rc = wasmDb.tzdb_exec(db, p, l);
  wasmDb.tzdb_free(p, l);
  return rc;
}
function dbPrepare(sql) {
  const [p, l] = dbStr(sql);
  const st = wasmDb.tzdb_prepare(db, p, l);
  wasmDb.tzdb_free(p, l);
  return st;
}
function storeMessage(peerId, fromId, date, msgId, out, text) {
  const st = dbPrepare(
    'INSERT INTO messages (id, peer_id, from_id, date, message, out, flags) VALUES (?,?,?,?,?,?,?)' +
    ' ON CONFLICT(id) DO UPDATE SET message=excluded.message;'
  );
  wasmDb.tzdb_bind_int64(st, 1, BigInt(msgId));
  wasmDb.tzdb_bind_int64(st, 2, BigInt(peerId));
  wasmDb.tzdb_bind_int64(st, 3, BigInt(fromId));
  wasmDb.tzdb_bind_int64(st, 4, BigInt(date));
  const [mp, ml] = dbStr(text);
  wasmDb.tzdb_bind_text(st, 5, mp, ml);
  wasmDb.tzdb_free(mp, ml);
  wasmDb.tzdb_bind_int(st, 6, out ? 1 : 0);
  wasmDb.tzdb_bind_int(st, 7, 0);
  const rc = wasmDb.tzdb_step(st);
  wasmDb.tzdb_finalize(st);
  return rc;
}
function loadHistory(peerId) {
  const rows = [];
  const sql = peerId
    ? 'SELECT id, peer_id, from_id, date, message, out FROM messages WHERE peer_id = ? ORDER BY date DESC, id DESC LIMIT 100;'
    : 'SELECT id, peer_id, from_id, date, message, out FROM messages ORDER BY date DESC, id DESC LIMIT 100;';
  const st = dbPrepare(sql);
  if (peerId) wasmDb.tzdb_bind_int64(st, 1, BigInt(peerId));
  while (wasmDb.tzdb_step(st) === 100) {
    const id = wasmDb.tzdb_column_int64(st, 0);
    const pid = wasmDb.tzdb_column_int64(st, 1);
    const fid = wasmDb.tzdb_column_int64(st, 2);
    const date = wasmDb.tzdb_column_int64(st, 3);
    const blen = wasmDb.tzdb_column_bytes(st, 4);
    const buf = wasmDb.tzdb_alloc(blen);
    const got = wasmDb.tzdb_column_blob(st, 4, buf, blen);
    const text = new TextDecoder().decode(new Uint8Array(dbMemory.buffer, buf, got));
    wasmDb.tzdb_free(buf, blen);
    const out = wasmDb.tzdb_column_int(st, 5);
    rows.push({ id: String(id), peerId: String(pid), fromId: String(fid), date: String(date), text, out: out !== 0 });
  }
  wasmDb.tzdb_finalize(st);
  return rows;
}

// ---------- boot: load both wasm modules ----------

async function init() {
  // 1) sqlite store (tz-db.wasm) over real OPFS
  postLog('init: OPFS root...');
  const root = await navigator.storage.getDirectory();
  const opfs = new OpfsBackend(root);
  postLog('init: preload db files...');
  await opfs.preload('sdk_store.db', true);
  await opfs.preload('sdk_store.db-journal', true);

  postLog('init: fetch tz-db.wasm...');
  const dbResp = await fetch('tz-db.wasm');
  if (!dbResp.ok) throw new Error('fetch tz-db.wasm: HTTP ' + dbResp.status);
  const dbBytes = await dbResp.arrayBuffer();
  const dec = new TextDecoder();
  const dbImports = { env: {
    js_opfs_open: (p, l, c) => { const n = dec.decode(new Uint8Array(dbMemory.buffer, p, l)); return opfs.open(n, c); },
    js_opfs_delete: (p, l) => { const n = dec.decode(new Uint8Array(dbMemory.buffer, p, l)); return opfs.delete(n); },
    js_opfs_access: (p, l) => { const n = dec.decode(new Uint8Array(dbMemory.buffer, p, l)); return opfs.access(n); },
    js_opfs_read: (fd, off, bp, len) => { const b = new Uint8Array(dbMemory.buffer, bp, len); return opfs.read(fd, off, b); },
    js_opfs_write: (fd, off, bp, len) => { const b = new Uint8Array(dbMemory.buffer, bp, len); return opfs.write(fd, off, b); },
    js_opfs_truncate: (fd, s) => opfs.truncate(fd, s),
    js_opfs_size: (fd) => BigInt(opfs.size(fd)),
    js_opfs_flush: (fd) => opfs.flush(fd),
    js_opfs_close: (fd) => opfs.close(fd),
    js_opfs_random: (p, l) => crypto.getRandomValues(new Uint8Array(dbMemory.buffer, p, l)),
    js_now_ms: () => BigInt(Math.floor(performance.now())),
  }};
  postLog('init: instantiate tz-db.wasm...');
  const dbMod = await WebAssembly.instantiate(dbBytes, dbImports);
  wasmDb = dbMod.instance.exports;
  dbMemory = wasmDb.memory;
  postLog('init: sqlite3_os_init...');
  if (typeof wasmDb.sqlite3_os_init === 'function') wasmDb.sqlite3_os_init();

  const [dp, dl] = dbStr('sdk_store.db');
  db = wasmDb.tzdb_open(dp, dl);
  wasmDb.tzdb_free(dp, dl);
  if (db < 0) throw new Error('tzdb_open failed');
  dbExec(
    'CREATE TABLE IF NOT EXISTS messages (' +
    'id INTEGER PRIMARY KEY, peer_id INTEGER NOT NULL, from_id INTEGER NOT NULL DEFAULT 0,' +
    'date INTEGER NOT NULL, message TEXT NOT NULL, media_type TEXT, media_data BLOB,' +
    'out INTEGER NOT NULL DEFAULT 0, flags INTEGER NOT NULL DEFAULT 0);' +
    'CREATE INDEX IF NOT EXISTS idx_messages_peer_date ON messages(peer_id, date DESC);'
  );
  postLog('sqlite store ready on OPFS');

  // 2) MTProto engine (tz.wasm)
  postLog('init: fetch tz.wasm...');
  const mtpResp = await fetch('tz.wasm');
  if (!mtpResp.ok) throw new Error('fetch tz.wasm: HTTP ' + mtpResp.status);
  const mtpBytes = await mtpResp.arrayBuffer();
  const mtpImports = { env: {
    js_log: (p, l) => { postLog('[wasm] ' + dec.decode(new Uint8Array(mtpMemory.buffer, p, l))); },
    js_on_status: (p, l) => { postLog('[status] ' + dec.decode(new Uint8Array(mtpMemory.buffer, p, l))); },
    js_on_qr: (p, l) => {
      const url = dec.decode(new Uint8Array(mtpMemory.buffer, p, l));
      self.postMessage({ type: 'qr', url });
    },
    js_on_login_success: (userId) => { self.postMessage({ type: 'login', userId: String(userId) }); },
    js_ws_send: (p, l) => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        const copy = new Uint8Array(mtpMemory.buffer, p, l).slice();
        ws.send(copy.buffer);
      }
    },
    js_random: (p, l) => crypto.getRandomValues(new Uint8Array(mtpMemory.buffer, p, l)),
    js_now_sec: () => Math.floor(Date.now() / 1000),
    js_now_ms_part: () => Math.floor(Date.now() % 1000),
    js_on_message: (peerId, fromId, date, msgId, out, tp, tl) => {
      const text = dec.decode(new Uint8Array(mtpMemory.buffer, tp, tl));
      postLog(`[msg] peer=${peerId} from=${fromId} date=${date} id=${msgId} out=${out}: ${text.slice(0, 60)}`);
      try {
        const rc = storeMessage(peerId, fromId, date, msgId, out, text);
        if (rc !== 101) postLog(`[store] step rc=${rc}`);
        self.postMessage({ type: 'stored', peerId: String(peerId), text: text.slice(0, 120) });
      } catch (e) {
        postLog('[store] failed: ' + e.message);
      }
    },
    js_on_migrate: (dcId) => {
      postLog('[migrate] switching to DC' + dcId);
      openSocket(dcId, true); // migrate: always fresh handshake
    },
    js_on_session_ready: () => {
      // Persist the fresh auth key so future loads skip the DH handshake.
      // Keyed by the current dc (auth key is per-DC).
      try {
        const sz = mtp.tz_export_session(0, 0);
        const buf = mtp.tz_alloc(sz || 280);
        const n = mtp.tz_export_session(buf, sz || 280);
        if (n > 0) {
          const blob = new Uint8Array(mtpMemory.buffer, buf, n).slice();
          const storedDc = n > 272 ? blob[272] : 0;
          mtp.tz_free(buf, n);
          idbSaveSession(blob, storedDc).then(() => postLog(`[session] saved to IndexedDB (dc${storedDc})`), (e) => postLog('[session] save failed: ' + e.message));
          idbSaveHomeDc(storedDc).catch(() => {});
        }
      } catch (e) {
        postLog('[session] export failed: ' + e.message);
      }
    },
  }};
  const mtpMod = await WebAssembly.instantiate(mtpBytes, mtpImports);
  mtp = mtpMod.instance.exports;
  mtpMemory = mtp.memory;
  postLog('MTProto engine ready');
  self.postMessage({ type: 'ready' });
}

let ws = null;
let engineCfg = null; // { apiId, apiHash, botToken }
let sessionKey = 'tz_session'; // IndexedDB key for persisted session

// --- IndexedDB session persistence (Tier-1 storage) ---
// Sessions are per-DC (auth key is per-DC), so blobs are keyed by dc id.
function idbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('tz-web', 1);
    req.onupgradeneeded = () => {
      const d = req.result;
      if (!d.objectStoreNames.contains('kv')) d.createObjectStore('kv');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
function idbSaveSession(bytes, dcId) {
  const key = 'tz_session_dc' + Math.abs(dcId);
  return idbOpen().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction('kv', 'readwrite');
    tx.objectStore('kv').put(bytes, key);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  }));
}
function idbLoadSession(dcId) {
  const key = 'tz_session_dc' + Math.abs(dcId);
  return idbOpen().then((db) => new Promise((resolve, reject) => {
    const req = db.transaction('kv', 'readonly').objectStore('kv').get(key);
    req.onsuccess = () => { db.close(); resolve(req.result || null); };
    req.onerror = () => { db.close(); reject(req.error); };
  }));
}
// Home DC: the DC the account actually lives on (per USER_MIGRATE). Storing it
// lets us connect straight to the right DC on the next load instead of probing
// DC2 and migrating again. Mirrors native SessionData.is_home.
function idbSaveHomeDc(dcId) {
  return idbOpen().then((db) => new Promise((resolve, reject) => {
    const tx = db.transaction('kv', 'readwrite');
    tx.objectStore('kv').put(Math.abs(dcId), 'tz_home_dc');
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  }));
}
function idbLoadHomeDc() {
  return idbOpen().then((db) => new Promise((resolve, reject) => {
    const req = db.transaction('kv', 'readonly').objectStore('kv').get('tz_home_dc');
    req.onsuccess = () => { db.close(); resolve(req.result || null); };
    req.onerror = () => { db.close(); reject(req.error); };
  }));
}

// Standard Telegram web DC endpoints. dc_id negative => test server.
const DC_URLS = {
  1: 'wss://pluto.web.telegram.org/apiws',
  2: 'wss://venus.web.telegram.org/apiws',
  3: 'wss://aurora.web.telegram.org/apiws',
  4: 'wss://vesta.web.telegram.org/apiws',
  5: 'wss://flora.web.telegram.org/apiws',
  '-1': 'wss://pluto.web.telegram.org/apiws_test',
  '-2': 'wss://venus.web.telegram.org/apiws_test',
  '-3': 'wss://aurora.web.telegram.org/apiws_test',
  '-4': 'wss://vesta.web.telegram.org/apiws_test',
  '-5': 'wss://flora.web.telegram.org/apiws_test',
};

function initEngine() {
  const enc = new TextEncoder();
  const hashBytes = enc.encode(engineCfg.apiHash);
  const hp = mtp.tz_alloc(hashBytes.length);
  new Uint8Array(mtpMemory.buffer, hp, hashBytes.length).set(hashBytes);
  mtp.tz_init(engineCfg.apiId, hp, hashBytes.length);
  mtp.tz_free(hp, hashBytes.length);
  if (engineCfg.botToken) {
    const tb = enc.encode(engineCfg.botToken);
    const tp = mtp.tz_alloc(tb.length);
    new Uint8Array(mtpMemory.buffer, tp, tb.length).set(tb);
    mtp.tz_set_bot_token(tp, tb.length);
    mtp.tz_free(tp, tb.length);
    postLog('[auth] bot token set');
  }
}

async function openSocket(dcId, isMigrate) {
  if (ws) { try { ws.close(); } catch (e) {} ws = null; }
  // Reset engine state (session/auth key cleared, stage -> idle, transport
  // reset). Auth key is per-DC, so migrate re-runs the whole handshake.
  if (typeof mtp.tz_reset === 'function') mtp.tz_reset();
  initEngine();
  mtp.tz_set_dc_id(dcId);

  // Restore a persisted session for THIS dc — skip the DH handshake. On
  // migrate the current key is provably wrong, so always do a fresh handshake.
  let restored = false;
  if (!isMigrate) {
    try {
      const saved = await idbLoadSession(dcId);
      if (saved && saved.byteLength > 0) {
        // SessionData layout: auth_key[256] auth_key_id[8] server_salt[8] dc_id[1]...
        const storedDc = saved.byteLength > 272 ? saved[272] : -1;
        postLog(`[session] stored blob dc=${storedDc} len=${saved.byteLength}`);
        const sp = mtp.tz_alloc(saved.byteLength);
        new Uint8Array(mtpMemory.buffer, sp, saved.byteLength).set(saved);
        restored = mtp.tz_import_session(sp, saved.byteLength) === 1;
        mtp.tz_free(sp, saved.byteLength);
      }
    } catch (e) {
      postLog('[session] load failed: ' + e.message);
    }
  }
  postLog(restored ? '[session] restored — skipping DH' : isMigrate ? '[session] migrate — fresh handshake' : '[session] none — full handshake');

  const url = DC_URLS[String(dcId)] || DC_URLS['2'];
  postLog(`[ws] connecting DC${dcId} ${url}`);
  ws = new WebSocket(url, ['binary']);
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => { postLog('[ws] open'); mtp.tz_ws_open(); };
  ws.onmessage = (ev) => {
    const data = new Uint8Array(ev.data);
    const p = mtp.tz_alloc(data.byteLength);
    new Uint8Array(mtpMemory.buffer, p, data.byteLength).set(data);
    mtp.tz_on_ws_chunk(p, data.byteLength);
    mtp.tz_free(p, data.byteLength);
  };
  ws.onerror = () => postLog('[ws] error');
  ws.onclose = () => postLog('[ws] closed');
}

function connect(dcUrl, apiId, apiHash, botToken) {
  engineCfg = { apiId, apiHash, botToken };
  let dcId = 2;
  if (dcUrl.includes('pluto')) dcId = 1;
  else if (dcUrl.includes('venus')) dcId = 2;
  else if (dcUrl.includes('aurora')) dcId = 3;
  else if (dcUrl.includes('vesta')) dcId = 4;
  else if (dcUrl.includes('flora')) dcId = 5;
  if (dcUrl.includes('_test')) dcId = -dcId;

  // If we already know the account's home DC (persisted after login), go
  // straight there — no DC2 probe + migrate on every load.
  idbLoadHomeDc().then((homeDc) => {
    if (homeDc && homeDc > 0) {
      const signed = dcId < 0 ? -homeDc : homeDc; // preserve test-server sign
      postLog(`[home] known DC${homeDc} — connecting directly`);
      openSocket(signed, false).catch((e) => postLog('[ws] open failed: ' + e.message));
    } else {
      openSocket(dcId, false).catch((e) => postLog('[ws] open failed: ' + e.message));
    }
  }).catch(() => {
    openSocket(dcId, false).catch((e) => postLog('[ws] open failed: ' + e.message));
  });
}

self.onmessage = (e) => {
  if (e.data.type === 'init') {
    postLog = (msg) => self.postMessage({ type: 'log', msg });
    init().then(() => {}, (err) => self.postMessage({ type: 'error', message: err.message, stack: err.stack }));
    return;
  }
  if (e.data.type === 'connect') {
    try { connect(e.data.dcUrl, e.data.apiId, e.data.apiHash, e.data.botToken || null); }
    catch (err) { self.postMessage({ type: 'error', message: err.message }); }
    return;
  }
  if (e.data.type === 'history') {
    try { self.postMessage({ type: 'history', rows: loadHistory(e.data.peerId || 0) }); }
    catch (err) { self.postMessage({ type: 'error', message: err.message }); }
    return;
  }
};
