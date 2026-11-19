/* Browser side of the Retro Blox server: window.claude.use('db' | 'room' | 'user') over one WebSocket. */
(function(){
  const ME = window.__ME;
  let ws = null, open = false, reqId = 0, sidSeq = 0; const pending = {}, queue = [], subsAll = {}, roomsAll = {}; let backoff = 500;
  const listeners = {conn:new Set()};
  function sendRaw(o){ const s = JSON.stringify(o); if(open) ws.send(s); else queue.push(s); }
  function request(o){ return new Promise((res, rej) => { const i = ++reqId; pending[i] = {res, rej}; sendRaw(Object.assign({i}, o)); setTimeout(() => { if(pending[i]){ delete pending[i]; rej({code:'timeout'}); } }, 15000); }); }
  function connect(){
    ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
    ws.onopen = () => { open = true; backoff = 500; Object.keys(subsAll).forEach(k => { const s = subsAll[k]; ws.send(JSON.stringify({op:'sub', sid:k, coll:s.coll, where:s.where, order:s.order, limit:s.limit})); }); Object.keys(roomsAll).forEach(rejoin); while(queue.length) ws.send(queue.shift()); listeners.conn.forEach(f => f(true)); };
    ws.onmessage = ev => { let m; try{ m = JSON.parse(ev.data); }catch(e){ return; } onMsg(m); };
    ws.onclose = () => { const was = open; open = false; Object.keys(pending).forEach(i => { pending[i].rej({code:'unavailable'}); delete pending[i]; }); if(was) listeners.conn.forEach(f => f(false)); if(ws && ws.status === 401) return; setTimeout(connect, backoff); backoff = Math.min(backoff * 2, 8000); };
  }
  function onMsg(m){
    if(m.i != null && pending[m.i]){ const p = pending[m.i]; delete pending[m.i]; if(m.ok) p.res(m); else { if(m.code === 'content_blocked' && window.onContentBlocked) try{ window.onContentBlocked(); }catch(e){} p.rej({code:m.code || 'error'}); } return; }
    if(m.t === 'snap'){ const s = subsAll[m.sid]; if(s) s.apply(m); }
    else if(m.t === 'peer' || m.t === 'left' || m.t === 'ev'){ const r = roomsAll[m.room]; if(r) r.onServer(m); }
  }
  /* ---- db ---- */
  const clone = o => JSON.parse(JSON.stringify(o));
  function docRef(p){ return {
    async get(){ const r = await request({op:'get', path:p}); return {exists:!!r.exists, id:p.split('/').pop(), data:() => r.d ? clone(r.d) : undefined}; },
    async set(d){ await request({op:'set', path:p, data:d}); }, async update(d){ await request({op:'update', path:p, data:d}); }, async delete(){ await request({op:'delete', path:p}); },
    async acquire(o){ const r = await request({op:'acquire', path:p, ttl:o && o.ttlMs}); return {acquired:!!r.acquired}; } }; }
  function coll(name, where, order, limit){
    const q = {
      where(f, op, v){ return coll(name, (where || []).concat([[f, op, v]]), order, limit); }, orderBy(f, dir){ return coll(name, where, [f, dir || 'asc'], limit); }, limit(n){ return coll(name, where, order, n); },
      doc(id){ return docRef(name + '/' + id); },
      async add(d){ const r = await request({op:'add', coll:name, data:d}); return {id:r.id}; },
      onSnapshot(next, err){
        const sid = 's' + (++sidSeq), map = new Map(); let first = true;
        subsAll[sid] = {coll:name, where:where || [], order, limit:limit || 0, apply(m){
          const changes = [], docs = m.docs || [];
          docs.forEach(d => { const had = map.has(d.id); map.set(d.id, d.d); changes.push({type:had ? 'modified' : 'added', id:d.id}); });
          const rm = (m.removed || []).slice(); if(m.init){ const have = new Set(docs.map(d => d.id)); map.forEach((v, id) => { if(!have.has(id)) rm.push(id); }); }
          rm.forEach(id => { if(map.delete(id)) changes.push({type:'removed', id}); });
          const all = [...map.entries()]; if(order){ const [f, dir] = order; all.sort((a, b) => (a[1][f] > b[1][f] ? 1 : a[1][f] < b[1][f] ? -1 : 0) * (dir === 'desc' ? -1 : 1)); }
          const mk = ([id, d]) => ({id, data:() => clone(d)});
          const snap = {docs:all.map(mk), docChanges:() => changes.map(c => ({type:c.type, doc:{id:c.id, data:() => clone(map.get(c.id) || {})}}))};
          first = false; try{ next(snap); }catch(e){ console.error(e); } } };
        sendRaw({op:'sub', sid, coll:name, where:where || [], order, limit:limit || 0});
        return () => { delete subsAll[sid]; sendRaw({op:'unsub', sid}); };
      } };
    return q;
  }
  const db = {collection:n => coll(n), doc:docRef};
  /* ---- room ---- */
  function mkRoom(name){
    let peer = null, myPres = {}; const peers = new Map(), handlers = {}, pcbs = new Set(); let ready, leftFlag = false;
    const notify = () => { const arr = [...peers.values()]; pcbs.forEach(f => { try{ f({peers:arr}); }catch(e){ console.error(e); } }); };
    const R = {
      onServer(m){
        if(m.t === 'peer'){ peers.set(m.peer, {peer:m.peer, by:m.by, isMe:false, kind:'viewer', presence:m.p || {}}); notify(); }
        else if(m.t === 'left'){ if(peers.delete(m.peer)) notify(); }
        else if(m.t === 'ev'){ (handlers[m.topic] || []).slice().forEach(f => { try{ f({topic:m.topic, data:m.data, by:m.by, peer:m.peer, isMe:false}); }catch(e){ console.error(e); } }); }
      },
      async join(){ peers.clear(); const r = await request({op:'join', room:name}); peer = r.peer; roomsAll[name] = roomsAll[name] || R; R.peerId = peer; (r.peers || []).forEach(p => peers.set(p.peer, {peer:p.peer, by:p.by, isMe:false, kind:'viewer', presence:p.p || {}})); peers.set(peer, {peer, by:ME.id, isMe:true, sameTab:true, kind:'viewer', presence:myPres}); if(Object.keys(myPres).length) sendRaw({op:'pres', room:name, peer, patch:myPres}); notify(); },
      peers:() => [...peers.values()],
      async presence(patch){ myPres = Object.assign({}, myPres, patch); if(peer){ const me = peers.get(peer); if(me) me.presence = myPres; sendRaw({op:'pres', room:name, peer, patch}); notify(); } },
      onPeers(f){ pcbs.add(f); setTimeout(() => { if(pcbs.has(f)) f({peers:[...peers.values()]}); }, 0); return () => pcbs.delete(f); },
      on(topic, f){ (handlers[topic] = handlers[topic] || []).push(f); return () => { handlers[topic] = (handlers[topic] || []).filter(x => x !== f); }; },
      async emit(topic, data){ if(peer) sendRaw({op:'emit', room:name, peer, topic, data}); },
      async leave(){ leftFlag = true; if(peer) sendRaw({op:'leave', room:name, peer}); delete roomsAll[name]; pcbs.clear(); },
      connected:() => open, onConnection(f){ listeners.conn.add(f); return () => listeners.conn.delete(f); } };
    roomsAll[name] = R; return R;
  }
  function rejoin(name){ const r = roomsAll[name]; if(r && r.join) r.join().catch(() => {}); }
  let lobby = null;
  async function getRoom(){ if(!lobby){ lobby = mkRoom(''); lobby.join().catch(() => {}); lobby.joinRoom = async n => { const r = mkRoom(n); await r.join(); return r; }; } return lobby; }
  const user = {async id(){ return ME.id; }, async me(){ return {id:ME.id, name:ME.name}; }, async profiles(ids){ const r = await fetch('/api/profiles', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ids})}); return r.json(); }, isOwner:() => false};
  window.claude = {async use(n){
    if(n === 'db') return db; if(n === 'user') return user;
    if(n === 'room'){ const r = await getRoom(); const o = Object.create(r); o.join = r.joinRoom; return o; }
    return null; }};
  connect();
})();
