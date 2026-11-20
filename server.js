'use strict';
/* Retro Blox server: accounts, document database, live rooms. No dependencies. Node 18+. */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = path.join(__dirname, 'public');
fs.mkdirSync(DATA_DIR, {recursive:true});
const DB_FILE = path.join(DATA_DIR, 'db.json');

/* ---------------- persistence ---------------- */
// Two modes. If UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN are set, everything is saved to that
// free hosted Redis database (survives restarts and free-tier sleeping). Otherwise it is saved to DATA_DIR/db.json.
const REDIS_URL = (process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/$/, ''), REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const USE_REDIS = !!(REDIS_URL && REDIS_TOKEN);
let S = {accounts:{}, sessions:{}, docs:{}};
const byLower = {};
let dirty = false, saving = false;
const saved = new Map(); // "hash\0field" -> json string last written
const HASHES = {accounts:'bp3:accounts', sessions:'bp3:sessions', docs:'bp3:docs'};
async function redis(cmds){
  const r = await fetch(REDIS_URL + (cmds.length === 1 && !Array.isArray(cmds[0][0]) ? '' : '/pipeline'), {method:'POST', headers:{Authorization:'Bearer ' + REDIS_TOKEN, 'Content-Type':'application/json'}, body:JSON.stringify(cmds.length === 1 ? cmds[0] : cmds)});
  if(!r.ok) throw new Error('redis ' + r.status); return r.json();
}
async function loadAll(){
  if(USE_REDIS){
    for(const k of Object.keys(HASHES)){
      const j = await redis([['HGETALL', HASHES[k]]]), arr = (j && j.result) || [];
      for(let i = 0; i < arr.length; i += 2){ try{ S[k][arr[i]] = JSON.parse(arr[i + 1]); saved.set(k + '\0' + arr[i], arr[i + 1]); }catch(e){} }
    }
    console.log('Loaded from Redis:', Object.keys(S.accounts).length, 'accounts,', Object.keys(S.docs).length, 'documents');
  } else { try{ S = Object.assign(S, JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); }catch(e){} }
  Object.keys(S.sessions).forEach(t => { if(S.sessions[t].exp < Date.now()) delete S.sessions[t]; });
  Object.values(S.accounts).forEach(a => byLower[a.lower] = a.id);
}
function markDirty(){ dirty = true; }
async function flush(sync){
  if(!dirty || (saving && !sync)) return; dirty = false; saving = true;
  try{
    if(USE_REDIS){
      const cmds = [], seen = new Set();
      for(const k of Object.keys(HASHES)) for(const f in S[k]){ const key = k + '\0' + f, v = JSON.stringify(S[k][f]); seen.add(key); if(saved.get(key) !== v) cmds.push(['HSET', HASHES[k], f, v, key, v]); }
      for(const key of [...saved.keys()]) if(!seen.has(key)){ const [k, f] = key.split('\0'); cmds.push(['HDEL', HASHES[k], f, key]); }
      let i = 0;
      while(i < cmds.length){
        let bytes = 0, j = i; while(j < cmds.length && j - i < 100 && (j === i || bytes + (cmds[j][3] || '').length < 500000)){ bytes += (cmds[j][3] || '').length + 60; j++; }
        const chunk = cmds.slice(i, j); await redis(chunk.map(c => c.slice(0, c[0] === 'HSET' ? 4 : 3)));
        chunk.forEach(c => { if(c[0] === 'HSET') saved.set(c[4], c[5]); else saved.delete(c[3]); });
        i = j;
      }
    } else {
      const tmp = DB_FILE + '.tmp', json = JSON.stringify(S);
      if(sync){ fs.writeFileSync(tmp, json); fs.renameSync(tmp, DB_FILE); } else await new Promise(res => fs.writeFile(tmp, json, err => err ? res() : fs.rename(tmp, DB_FILE, () => res())));
    }
  }catch(e){ dirty = true; console.error('save failed', e.message); }
  saving = false;
}
setInterval(() => flush(false), 1500);
for(const sig of ['SIGINT', 'SIGTERM']) process.on(sig, async () => { try{ await flush(true); }catch(e){} process.exit(0); });

/* ---------------- auth ---------------- */
const NAME_RE = /^[A-Za-z0-9_]{3,20}$/;
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const newToken = () => crypto.randomBytes(24).toString('hex');
function cookieOf(req, k){ const m = (req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(k + '=')); return m ? decodeURIComponent(m.slice(k.length + 1)) : null; }
function userOf(req){ const t = cookieOf(req, 'bp3'); const s = t && S.sessions[t]; if(!s || s.exp < Date.now()) return null; if(S.docs['bans/' + s.uid]) return null; return S.accounts[s.uid] || null; }
function startSession(res, uid, req){
  const t = newToken(); S.sessions[t] = {uid, exp:Date.now() + 180 * 86400000}; markDirty();
  const secure = (req.headers['x-forwarded-proto'] || '').includes('https') ? '; Secure' : '';
  res.setHeader('Set-Cookie', 'bp3=' + t + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + 180 * 86400 + secure);
}
const attempts = {};
function throttled(ip){ const now = Date.now(), a = attempts[ip] = (attempts[ip] || []).filter(t => now - t < 600000); if(a.length >= 20) return true; a.push(now); return false; }
function newId(){ return 'u_' + crypto.randomBytes(9).toString('hex'); }

/* ---------------- document store ---------------- */
const MAXDOC = 256 * 1024;
const subs = new Set(); // {conn, sid, coll, where, order, limit, sent:Map id->version}
const leases = {};
const segs = p => p.split('/');
const validPath = p => typeof p === 'string' && p.length < 400 && /^[A-Za-z0-9_\-.~:@+]{1,200}(\/[A-Za-z0-9_\-.~:@+]{1,200})*$/.test(p);
function allowRead(uid, collPath){ const s = segs(collPath); if(s[0] === 'data' && s[1] === 'users') return s[2] === uid; return true; }
// write rules per collection: returns true when allowed
const smallImg = v => v == null || (typeof v === 'string' && v.length < 60000 && (v === '' || v.startsWith('data:image/')));
const validItem = d => ['shirt', 'pants'].includes(d.type) && typeof d.name === 'string' && d.name.length >= 2 && d.name.length <= 40 && Number.isInteger(d.price) && d.price >= 0 && d.price <= 1000 && smallImg(d.img);

/* ---- word filter ---- */
const BAD_WORDS = ['fuck','fucker','fucking','shit','shitty','bitch','bastard','asshole','dick','dickhead','cock','pussy','cunt','whore','slut','nigger','nigga','faggot','fag','retard','retarded','rape','rapist','nazi','hitler','porn','sex','sexy','nude','nudes','penis','vagina','boob','boobs','cum','kys'];
const BAD_SUB = BAD_WORDS.filter(w => w.length >= 5);
const LEET = {'0':'o','1':'i','3':'e','4':'a','5':'s','7':'t','@':'a','$':'s','!':'i','+':'t'};
function badText(str){
  const t = String(str || '').toLowerCase().replace(/[01345 7@$!+]/g, c => LEET[c] || c).replace(/(.)\1{2,}/g, '$1$1');
  const words = t.split(/[^a-z]+/).filter(Boolean); if(words.some(w => BAD_WORDS.includes(w))) return true;
  const packed = t.replace(/[^a-z]/g, ''); return BAD_SUB.some(w => packed.includes(w));
}
const SKIP_KEYS = new Set(['img', 'icon', 'bricks', 'state', 'c', 'ids']);
function docHasBad(v, depth){ depth = depth || 0; if(depth > 3 || v == null) return false; if(typeof v === 'string') return v.length < 3000 && badText(v); if(Array.isArray(v)) return v.slice(0, 40).some(x => docHasBad(x, depth + 1)); if(typeof v === 'object') return Object.keys(v).some(k => !SKIP_KEYS.has(k) && docHasBad(v[k], depth + 1)); return false; }
const FILTERED = new Set(['messages', 'wall', 'feed', 'groups', 'games', 'items', 'ads', 'profiles', 'names', 'models', 'cplaces']);
function bricksBad(str){ if(typeof str !== 'string') return false; const rows = str.split(';'); for(let i = 0; i < rows.length && i < 1200; i++){ const k = rows[i].indexOf('|'); if(k < 0) continue; let t = ''; try{ t = decodeURIComponent(rows[i].slice(k + 1)); }catch(e){ return true; } if(t.length > 80 || badText(t)) return true; } return false; }
const validEnv = e => e == null || (typeof e === 'object' && !Array.isArray(e) && Object.keys(e).every(k => ({tod:[0, 24], fog:[0, 100], grav:[30, 200], walk:[8, 40], jump:[30, 90], music:[0, 12]})[k] && typeof e[k] === 'number' && e[k] >= ({tod:[0, 24], fog:[0, 100], grav:[30, 200], walk:[8, 40], jump:[30, 90], music:[0, 12]})[k][0] && e[k] <= ({tod:[0, 24], fog:[0, 100], grav:[30, 200], walk:[8, 40], jump:[30, 90], music:[0, 12]})[k][1]));
const ADMINS = new Set((process.env.ADMIN_USERS || '').toLowerCase().split(',').map(x => x.trim()).filter(Boolean));
const isAdmin = uid => !!(S.accounts[uid] && ADMINS.has(S.accounts[uid].lower));
const blockedPair = (a, b) => !!(S.docs['blocks/' + a + '_' + b] || S.docs['blocks/' + b + '_' + a]);
const REPORT_REASONS = ['inappropriate', 'harassment', 'scam', 'cheating', 'other'];
function allowWrite(uid, p, op, data, old){
  const s = segs(p), col = s[0], id = s[s.length - 1];
  if(col === 'data'){ return s[1] === 'users' && s[2] === uid; }
  if(s.length !== 2) return false;
  const mine = x => x === uid;
  switch(col){
    case 'profiles': return id === uid;
    case 'names': return op === 'delete' ? !!old && old.uid === uid : (!old || old.uid === uid) && data && data.uid === uid;
    case 'friends': { if(op === 'delete') return !!old && (old.ids || []).includes(uid); if(!(data && Array.isArray(data.ids) && data.ids.length === 2 && data.ids.includes(uid) && id === data.ids.slice().sort().join('__'))) return false; if(old) return true; const other = data.ids.find(x => x !== uid); return !!S.docs['requests/' + other + '_' + uid] && !blockedPair(uid, other); }
    case 'requests': return op === 'delete' ? !!old && (old.from === uid || old.to === uid) : data && mine(data.from) && id === data.from + '_' + data.to && !blockedPair(data.from, data.to);
    case 'blocks': return op === 'delete' ? !!old && old.by === uid : !old && data && mine(data.by) && typeof data.who === 'string' && data.who !== uid && id === uid + '_' + data.who;
    case 'bans': return isAdmin(uid);
    case 'scores': { if(op === 'delete') return !!old && old.uid === uid; const n = (v, mx) => v == null || (typeof v === 'number' && isFinite(v) && v >= 0 && v <= mx); return !!data && mine(data.uid) && typeof data.gid === 'string' && data.gid.length < 30 && id === data.gid + '_' + uid && n(data.t, 36000) && n(data.s, 1000000) && typeof data.name === 'string'; }
    case 'reports': return isAdmin(uid) ? true : op === 'set' && !old && data && mine(data.by) && typeof data.who === 'string' && data.who !== uid && REPORT_REASONS.includes(data.reason) && String(data.detail || '').length <= 400 && String(data.ctx || '').length <= 80;
    case 'messages': return op === 'delete' ? !!old && (old.from === uid || old.to === uid) : !old && data && mine(data.from) && typeof data.to === 'string' && !blockedPair(uid, data.to);
    case 'trades': return op === 'delete' ? false : old ? (old.from === uid || old.to === uid) && data && data.from === old.from && data.to === old.to : data && mine(data.from) && !blockedPair(data.from, data.to);
    case 'groups': return op === 'delete' ? !!old && old.owner === uid : old ? old.owner === uid : data && mine(data.owner);
    case 'members': return op === 'delete' ? !!old && old.uid === uid : data && mine(data.uid) && id === data.gid + '_' + uid;
    case 'wall': case 'feed': return op === 'delete' ? !!old && old.uid === uid : !old && data && mine(data.uid);
    case 'votes': return data ? mine(data.uid) && id.endsWith('_' + uid) : id.endsWith('_' + uid);
    case 'models': return op === 'delete' ? !!old && old.owner === uid : data && typeof data.name === 'string' && data.name.length >= 3 && data.name.length <= 40 && typeof data.bricks === 'string' && data.bricks.length < 30000 && Number.isInteger(data.n) && data.n >= 1 && data.n <= 200 && typeof data.by === 'string' && data.by.length <= 30 && (old ? old.owner === uid && data.owner === uid : mine(data.owner));
    case 'cplaces': { if(op === 'delete') return !!old && old.owner === uid; const okEds = x => Array.isArray(x) && x.length >= 1 && x.length <= 8 && x.every(i => typeof i === 'string' && S.accounts[i]) && x.includes(data.owner);
      if(!data || typeof data.bricks !== 'string' || data.bricks.length > 150000 || typeof data.name !== 'string' || data.name.length > 40 || !validEnv(data.env) || !okEds(data.eds)) return false;
      if(!old) return mine(data.owner) && data.eds.includes(uid);
      if(data.owner !== old.owner) return false; if(old.owner === uid) return true; return old.eds.includes(uid) && JSON.stringify(data.eds) === JSON.stringify(old.eds); }
    case 'pvers': return op === 'delete' ? !!old && old.owner === uid : data && mine(data.owner) && id.startsWith(uid + '_') && Array.isArray(data.v) && data.v.length <= 10 && data.v.every(x => x && typeof x.b === 'string' && x.b.length < 60000 && Number.isFinite(x.t) && Number.isInteger(x.n));
    case 'games': return op === 'delete' ? !!old && old.owner === uid : data && validEnv(data.env) && smallImg(data.icon) && (old ? old.owner === uid && data.owner === uid : mine(data.owner));
    case 'items': return op === 'delete' ? !!old && old.creator === uid : data && validItem(data) && (old ? old.creator === uid && data.creator === uid : mine(data.creator));
    case 'ads': return op === 'delete' ? !!old && old.owner === uid : data && smallImg(data.img) && (old ? old.owner === uid && data.owner === uid : mine(data.owner));
    case 'sales': return op === 'delete' ? !!old && old.seller === uid : old ? old.seller === uid && data && data.seller === old.seller && data.buyer === old.buyer && data.amt === old.amt && data.item === old.item : data && mine(data.buyer) && typeof data.seller === 'string' && Number.isInteger(data.amt) && data.amt >= 0 && data.amt <= 2000;
    default: return false;
  }
}
function visible(uid, coll, id, d){ // per-doc read privacy
  if(coll === 'messages') return d.from === uid || d.to === uid;
  if(coll === 'trades' || coll === 'requests') return d.from === uid || d.to === uid;
  if(coll === 'sales') return d.seller === uid || d.buyer === uid;
  if(coll === 'blocks') return d.by === uid;
  if(coll === 'reports') return d.by === uid || isAdmin(uid);
  if(coll === 'bans') return isAdmin(uid);
  if(coll === 'pvers') return d.owner === uid;
  if(coll === 'cplaces') return Array.isArray(d.eds) && d.eds.includes(uid);
  if(coll === 'friends') return (d.ids || []).includes(uid);
  return true;
}
function cmp(a, b){ return a < b ? -1 : a > b ? 1 : 0; }
function matches(d, where){ return where.every(([f, op, v]) => op === 'array-contains' ? Array.isArray(d[f]) && d[f].includes(v) : op === '==' || op === 'eq' ? d[f] === v : false); }
function runQuery(sub){
  const prefix = sub.coll + '/', out = [];
  for(const k in S.docs){ if(!k.startsWith(prefix)) continue; const rest = k.slice(prefix.length); if(rest.includes('/')) continue; const e = S.docs[k]; if(!visible(sub.conn.uid, sub.coll, rest, e.d)) continue; if(!matches(e.d, sub.where)) continue; out.push({id:rest, d:e.d, v:e.v}); }
  if(sub.order){ const [f, dir] = sub.order; out.sort((a, b) => cmp(a.d[f], b.d[f]) * (dir === 'desc' ? -1 : 1)); }
  return sub.limit ? out.slice(0, sub.limit) : out;
}
function pushSub(sub){
  const res = runQuery(sub), now = new Map(), docs = [], removed = [];
  res.forEach(r => { now.set(r.id, r.v); if(sub.sent.get(r.id) !== r.v) docs.push({id:r.id, d:r.d, v:r.v}); });
  sub.sent.forEach((v, id) => { if(!now.has(id)) removed.push(id); });
  if(!docs.length && !removed.length && sub.initDone) return; const init = !sub.initDone; sub.sent = now; sub.initDone = true;
  send(sub.conn, {t:'snap', sid:sub.sid, docs, removed, init});
}
function notifyColl(coll){ subs.forEach(s => { if(s.coll === coll) pushSub(s); }); }
function writeDoc(uid, op, p, data){
  if(!validPath(p)) return {code:'invalid_argument'};
  const e = S.docs[p], old = e ? e.d : null;
  if(op !== 'delete' && FILTERED.has(p.split('/')[0]) && data && (docHasBad(data) || bricksBad(data.bricks))) return {code:'content_blocked'};
  if(op === 'delete'){ if(!e) return {ok:true}; if(!allowWrite(uid, p, 'delete', null, old)) return {code:'permission_denied'}; delete S.docs[p]; }
  else {
    if(!data || typeof data !== 'object' || Array.isArray(data)) return {code:'invalid_argument'};
    const next = op === 'update' ? Object.assign({}, old || {}, data) : data;
    if(JSON.stringify(next).length > MAXDOC) return {code:'invalid_argument'};
    if(!allowWrite(uid, p, op, next, old)) return {code:'permission_denied'};
    S.docs[p] = {d:next, v:(e ? e.v : 0) + 1};
    if(p.startsWith('reports/')) console.log('REPORT', JSON.stringify(next));
  }
  markDirty(); const s = segs(p); notifyColl(s.slice(0, -1).join('/')); return {ok:true};
}

/* ---------------- websocket (RFC 6455, no deps) ---------------- */
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function frame(op, payload){
  const len = payload.length; let h;
  if(len < 126){ h = Buffer.alloc(2); h[1] = len; } else if(len < 65536){ h = Buffer.alloc(4); h[1] = 126; h.writeUInt16BE(len, 2); } else { h = Buffer.alloc(10); h[1] = 127; h.writeBigUInt64BE(BigInt(len), 2); }
  h[0] = 0x80 | op; return Buffer.concat([h, payload]);
}
function send(conn, obj){ if(conn.dead) return; try{ conn.socket.write(frame(1, Buffer.from(JSON.stringify(obj)))); }catch(e){} }
const conns = new Set();
const rooms = {}; // name -> Map peer -> {conn, by, p}
let peerSeq = 0;
function leaveRoom(conn, name, peer){
  const r = rooms[name]; if(!r || !r.has(peer)) return; r.delete(peer); conn.peers.delete(peer);
  r.forEach(m => send(m.conn, {t:'left', room:name, peer})); if(!r.size) delete rooms[name];
}
function cleanup(conn){
  if(conn.dead) return; conn.dead = true; conns.delete(conn);
  subs.forEach(s => { if(s.conn === conn) subs.delete(s); });
  [...conn.peers].forEach(k => { const [name, peer] = k.split('\u0000'); leaveRoom(conn, name, peer); conn.peers.delete(k); });
  try{ conn.socket.destroy(); }catch(e){}
}
const ROOM_RE = /^[a-z0-9_.-]{0,48}$/;
function handle(conn, m){
  const uid = conn.uid; if(!m || typeof m !== 'object') return;
  const now = Date.now(); if(now - conn.win > 1000){ conn.win = now; conn.cnt = 0; } if(++conn.cnt > 150) return;
  const reply = (ok, extra) => { if(m.i != null) send(conn, Object.assign({i:m.i, ok}, extra)); };
  switch(m.op){
    case 'get': { if(!validPath(m.path) || !allowRead(uid, m.path.split('/').slice(0, -1).join('/'))) return reply(false, {code:'permission_denied'}); const e = S.docs[m.path]; if(e && !visible(uid, segs(m.path)[0], '', e.d)) return reply(true, {exists:false}); return reply(true, {exists:!!e, d:e ? e.d : null}); }
    case 'set': case 'update': case 'delete': { const r = writeDoc(uid, m.op, m.path, m.data); return reply(!!r.ok, r.code ? {code:r.code} : {}); }
    case 'add': { const id = Date.now().toString(36) + crypto.randomBytes(3).toString('hex'); if(typeof m.coll !== 'string') return reply(false, {code:'invalid_argument'}); const r = writeDoc(uid, 'set', m.coll + '/' + id, m.data); return reply(!!r.ok, r.code ? {code:r.code} : {id}); }
    case 'acquire': { const k = m.path, l = leases[k], t = Date.now(); if(l && l.exp > t && l.holder !== uid) return reply(true, {acquired:false}); leases[k] = {holder:uid, exp:t + Math.min(Math.max(+m.ttl || 5000, 1000), 600000)}; return reply(true, {acquired:true}); }
    case 'sub': { if(typeof m.coll !== 'string' || !validPath(m.coll) || !allowRead(uid, m.coll)) return; if(conn.nsub > 80) return; conn.nsub++; const sub = {conn, sid:m.sid, coll:m.coll, where:Array.isArray(m.where) ? m.where.slice(0, 5) : [], order:m.order || null, limit:Math.min(+m.limit || 0, 1000), sent:new Map(), initDone:false}; subs.add(sub); pushSub(sub); return; }
    case 'unsub': { subs.forEach(s => { if(s.conn === conn && s.sid === m.sid){ subs.delete(s); conn.nsub--; } }); return; }
    case 'join': {
      const name = String(m.room || ''); if(!ROOM_RE.test(name) || conn.peers.size > 6) return reply(false, {code:'invalid_argument'});
      const peer = 'p' + (++peerSeq).toString(36), r = rooms[name] = rooms[name] || new Map();
      const existing = []; r.forEach((mm, k) => existing.push({peer:k, by:mm.by, p:mm.p}));
      r.set(peer, {conn, by:uid, p:{}}); conn.peers.add(name + '\u0000' + peer);
      reply(true, {peer, peers:existing}); r.forEach((mm, k) => { if(k !== peer) send(mm.conn, {t:'peer', room:name, peer, by:uid, p:{}}); }); return;
    }
    case 'pres': { const r = rooms[m.room], me = r && r.get(m.peer); if(!me || me.conn !== conn || !m.patch || typeof m.patch !== 'object') return; const merged = Object.assign({}, me.p, m.patch); if(JSON.stringify(merged).length > 4000) return; Object.keys(merged).forEach(k => { if(merged[k] === null) delete merged[k]; }); me.p = merged; r.forEach((mm, k) => { if(k !== m.peer) send(mm.conn, {t:'peer', room:m.room, peer:m.peer, by:uid, p:merged}); }); return; }
    case 'emit': { const r = rooms[m.room], me = r && r.get(m.peer); if(!me || me.conn !== conn || typeof m.topic !== 'string' || m.topic.length > 40) return; if(JSON.stringify(m.data || null).length > 2000) return; const to = m.topic === 'dm' && m.data && m.data.to; r.forEach((mm, k) => { if(k === m.peer) return; if(to && mm.by !== to) return; send(mm.conn, {t:'ev', room:m.room, peer:m.peer, by:uid, topic:m.topic, data:m.data}); }); return; }
    case 'leave': { leaveRoom(conn, String(m.room || ''), m.peer); return; }
  }
}
function onUpgrade(req, socket){
  const u = userOf(req); const origin = req.headers.origin;
  if(!u || req.url.split('?')[0] !== '/ws' || (origin && new URL(origin).host !== req.headers.host)){ socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); return socket.destroy(); }
  const key = req.headers['sec-websocket-key']; if(!key){ return socket.destroy(); }
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + crypto.createHash('sha1').update(key + GUID).digest('base64') + '\r\n\r\n');
  socket.setNoDelay(true);
  const conn = {socket, uid:u.id, dead:false, peers:new Set(), nsub:0, win:0, cnt:0}; conns.add(conn);
  let buf = Buffer.alloc(0), frag = [];
  socket.on('data', d => {
    buf = Buffer.concat([buf, d]); if(buf.length > 2 * 1024 * 1024) return cleanup(conn);
    for(;;){
      if(buf.length < 2) break; const fin = buf[0] & 0x80, op = buf[0] & 15, masked = buf[1] & 0x80; let len = buf[1] & 127, off = 2;
      if(len === 126){ if(buf.length < 4) break; len = buf.readUInt16BE(2); off = 4; } else if(len === 127){ if(buf.length < 10) break; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      if(len > 1024 * 1024) return cleanup(conn); if(!masked) return cleanup(conn);
      if(buf.length < off + 4 + len) break;
      const mask = buf.slice(off, off + 4), pay = Buffer.from(buf.slice(off + 4, off + 4 + len)); for(let i = 0; i < pay.length; i++) pay[i] ^= mask[i & 3]; buf = buf.slice(off + 4 + len);
      if(op === 8){ try{ socket.write(frame(8, Buffer.alloc(0))); }catch(e){} return cleanup(conn); }
      if(op === 9){ try{ socket.write(frame(10, pay)); }catch(e){} continue; } if(op === 10) continue;
      if(op === 0 || op === 1){ frag.push(pay); if(fin){ const txt = Buffer.concat(frag).toString('utf8'); frag = []; let m; try{ m = JSON.parse(txt); }catch(e){ continue; } try{ handle(conn, m); }catch(e){ console.error('handler error', e); } } }
    }
  });
  socket.on('close', () => cleanup(conn)); socket.on('error', () => cleanup(conn));
  send(conn, {t:'hello', uid:u.id});
}

/* ---------------- http ---------------- */
const MIME = {'.html':'text/html; charset=utf-8', '.js':'text/javascript', '.png':'image/png', '.webmanifest':'application/manifest+json', '.json':'application/json', '.svg':'image/svg+xml', '.ico':'image/x-icon'};
const APP = () => fs.readFileSync(path.join(PUB, 'app.html'), 'utf8');
function json(res, code, obj){ res.writeHead(code, {'Content-Type':'application/json', 'Cache-Control':'no-store'}); res.end(JSON.stringify(obj)); }
function body(req, cb){ let b = ''; req.on('data', c => { b += c; if(b.length > 10000) req.destroy(); }); req.on('end', () => { try{ cb(JSON.parse(b || '{}')); }catch(e){ cb(null); } }); }
function deleteAccount(a){
  Object.keys(S.docs).forEach(k => { if(k.startsWith('data/users/' + a.id + '/') || k === 'profiles/' + a.id || k === 'names/' + a.lower) delete S.docs[k]; });
  Object.keys(S.sessions).forEach(t => { if(S.sessions[t].uid === a.id) delete S.sessions[t]; });
  delete S.accounts[a.id]; delete byLower[a.lower]; markDirty(); ['profiles', 'names'].forEach(notifyColl);
}
const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0], ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'same-origin');
  if(req.method === 'POST' && url === '/api/signup'){ return body(req, b => {
    if(!b || throttled(ip)) return json(res, 429, {error:'Too many tries. Wait a few minutes.'});
    const name = String(b.username || '').trim(), pw = String(b.password || '');
    if(!NAME_RE.test(name)) return json(res, 400, {error:'Usernames are 3 to 20 characters: letters, numbers and underscores.'});
    if(badText(name)) return json(res, 400, {error:'That username is not allowed. Please choose another.'});
    if(pw.length < 6 || pw.length > 100) return json(res, 400, {error:'Your password must be at least 6 characters.'});
    if(pw.toLowerCase() === name.toLowerCase()) return json(res, 400, {error:'Your password cannot be the same as your username.'});
    if(byLower[name.toLowerCase()]) return json(res, 409, {error:'That username is already taken.'});
    const salt = crypto.randomBytes(16).toString('hex'), a = {id:newId(), name, lower:name.toLowerCase(), salt, hash:hashPw(pw, salt), created:Date.now()};
    S.accounts[a.id] = a; byLower[a.lower] = a.id; markDirty(); startSession(res, a.id, req); json(res, 200, {ok:true});
  }); }
  if(req.method === 'POST' && url === '/api/login'){ return body(req, b => {
    if(!b || throttled(ip)) return json(res, 429, {error:'Too many tries. Wait a few minutes.'});
    const a = S.accounts[byLower[String(b.username || '').trim().toLowerCase()]], pw = String(b.password || '');
    if(!a || !crypto.timingSafeEqual(Buffer.from(hashPw(pw, a.salt), 'hex'), Buffer.from(a.hash, 'hex'))) return json(res, 401, {error:'Incorrect username or password.'});
    if(S.docs['bans/' + a.id]) return json(res, 403, {error:'This account has been banned.'});
    startSession(res, a.id, req); json(res, 200, {ok:true});
  }); }
  if(req.method === 'POST' && url === '/api/logout'){ const t = cookieOf(req, 'bp3'); if(t){ delete S.sessions[t]; markDirty(); } res.setHeader('Set-Cookie', 'bp3=; Path=/; Max-Age=0'); return json(res, 200, {ok:true}); }
  if(req.method === 'POST' && url === '/api/delete'){ const a = userOf(req); if(!a) return json(res, 401, {}); deleteAccount(a); res.setHeader('Set-Cookie', 'bp3=; Path=/; Max-Age=0'); return json(res, 200, {ok:true}); }
  if(req.method === 'POST' && url === '/api/profiles'){ const a = userOf(req); if(!a) return json(res, 401, {}); return body(req, b => { const o = {}; ((b && b.ids) || []).slice(0, 64).forEach(i => { const x = S.accounts[i]; if(x) o[i] = {name:x.name}; }); json(res, 200, o); }); }
  if(req.method === 'GET' && url === '/healthz') return json(res, 200, {ok:true});
  if(req.method !== 'GET' && req.method !== 'HEAD'){ res.writeHead(405); return res.end(); }
  if(url === '/' || url === '/index.html'){
    const u = userOf(req);
    if(!u){ res.writeHead(200, {'Content-Type':MIME['.html'], 'Cache-Control':'no-store'}); return res.end(fs.readFileSync(path.join(PUB, 'login.html'))); }
    const me = JSON.stringify({id:u.id, name:u.name, admin:isAdmin(u.id)}).replace(/</g, '\\u003c');
    res.writeHead(200, {'Content-Type':MIME['.html'], 'Cache-Control':'no-store'}); return res.end(APP().replace('/*ME*/', me));
  }
  const f = path.join(PUB, path.normalize(url).replace(/^(\.\.[\/\\])+/, ''));
  if(!f.startsWith(PUB) || f.endsWith('app.html') || f.endsWith('login.html')){ res.writeHead(404); return res.end('Not found'); }
  fs.readFile(f, (err, buf) => { if(err){ res.writeHead(404); return res.end('Not found'); } res.writeHead(200, {'Content-Type':MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control':'public, max-age=3600'}); res.end(buf); });
});
server.on('upgrade', onUpgrade);
loadAll().then(() => server.listen(PORT, () => console.log('Retro Blox running on http://localhost:' + PORT + (USE_REDIS ? '  (data in Redis)' : '  (data in ' + DATA_DIR + ')')))).catch(e => { console.error('Could not load saved data:', e.message); process.exit(1); });
