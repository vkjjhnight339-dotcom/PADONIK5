// เซิร์ฟเวอร์ร้านค้า — ไม่ต้อง npm install (ใช้ Node 22.5+)  รัน: node server.js
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');
const PORT = process.env.PORT || 3000;
const db = new DatabaseSync(path.join(__dirname, 'shop.db'));
db.exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, email TEXT UNIQUE COLLATE NOCASE, salt TEXT, hash TEXT, balance REAL DEFAULT 0, role TEXT DEFAULT 'user', created INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER, expires INTEGER);
CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY, name TEXT, img TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT, price REAL, img TEXT DEFAULT '', category_id INTEGER, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS stock(id INTEGER PRIMARY KEY, product_id INTEGER, data TEXT, sold INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER, product_id INTEGER, name TEXT, price REAL, data TEXT, created INTEGER);
CREATE TABLE IF NOT EXISTS topups(id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, ref TEXT, status TEXT DEFAULT 'pending', created INTEGER);
`);
const q = (s, ...a) => db.prepare(s).all(...a), one = (s, ...a) => db.prepare(s).get(...a), run = (s, ...a) => db.prepare(s).run(...a);
const now = () => Date.now(), fail = (c, m) => { throw Object.assign(new Error(m), { code: c }) };

const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
function session(req) {
  const t = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || '')?.[1];
  if (!t) return null;
  return one('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?', t, now()) || null;
}
const pub = u => u && { id: u.id, username: u.username, email: u.email, balance: u.balance, role: u.role };
const hits = new Map();
function limit(ip, max = 10) { const h = (hits.get(ip) || []).filter(t => now() - t < 600000); h.push(now()); hits.set(ip, h); if (h.length > max) fail(429, 'ลองบ่อยเกินไป รอสักครู่'); }
const clean = s => String(s ?? '').trim();

const routes = {
  'POST /api/register'(req, b, res) {
    limit(req.socket.remoteAddress);
    const u = clean(b.username), e = clean(b.email), p = String(b.password ?? '');
    if (!/^[A-Za-z0-9_]{4,20}$/.test(u)) fail(400, 'ชื่อผู้ใช้ไม่ถูกต้อง');
    if (!/^\S+@\S+\.\S+$/.test(e)) fail(400, 'อีเมลไม่ถูกต้อง');
    if (p.length < 8 || !/[A-Za-z]/.test(p) || !/\d/.test(p)) fail(400, 'รหัสผ่านต้อง 8 ตัวขึ้นไป มีตัวอักษรและตัวเลข');
    if (one('SELECT 1 FROM users WHERE username=?', u)) fail(409, 'ชื่อผู้ใช้นี้ถูกใช้แล้ว');
    if (one('SELECT 1 FROM users WHERE email=?', e)) fail(409, 'อีเมลนี้ถูกใช้แล้ว');
    const salt = crypto.randomBytes(16).toString('hex'), first = !one('SELECT 1 FROM users');
    const r = run('INSERT INTO users(username,email,salt,hash,role,created) VALUES(?,?,?,?,?,?)', u, e, salt, hashPw(p, salt), first ? 'admin' : 'user', now());
    return startSession(res, r.lastInsertRowid);
  },
  'POST /api/login'(req, b, res) {
    limit(req.socket.remoteAddress);
    const u = one('SELECT * FROM users WHERE username=?', clean(b.username));
    if (!u || !crypto.timingSafeEqual(Buffer.from(u.hash, 'hex'), Buffer.from(hashPw(String(b.password ?? ''), u.salt), 'hex'))) fail(401, 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
    return startSession(res, u.id);
  },
  'POST /api/logout'(req, b, res) {
    const t = /sid=([a-f0-9]+)/.exec(req.headers.cookie || '')?.[1]; if (t) run('DELETE FROM sessions WHERE token=?', t);
    res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0'); return { ok: true };
  },
  'GET /api/me'(req, b, res, me) { return { user: pub(me) }; },
  'GET /api/shop'() {
    return {
      categories: q('SELECT c.*,(SELECT COUNT(*) FROM products WHERE category_id=c.id AND active=1) n FROM categories c'),
      products: q('SELECT p.id,p.name,p.price,p.img,p.category_id,(SELECT COUNT(*) FROM stock WHERE product_id=p.id AND sold=0) stock FROM products p WHERE active=1'),
      stats: { users: one('SELECT COUNT(*) n FROM users').n, products: one('SELECT COUNT(*) n FROM products WHERE active=1').n, stock: one('SELECT COUNT(*) n FROM stock WHERE sold=0').n, sold: one('SELECT COUNT(*) n FROM orders').n },
      feed: q("SELECT substr(u.username,1,2)||'***' who, o.name, o.created FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 8")
    };
  },
  'POST /api/buy'(req, b, res, me) {
    if (!me) fail(401, 'กรุณาเข้าสู่ระบบ');
    const id = +b.id; let out;
    db.exec('BEGIN IMMEDIATE');
    try {
      const p = one('SELECT * FROM products WHERE id=? AND active=1', id), u = one('SELECT balance FROM users WHERE id=?', me.id);
      if (!p) fail(404, 'ไม่พบสินค้า');
      const s = one('SELECT * FROM stock WHERE product_id=? AND sold=0 ORDER BY id LIMIT 1', id);
      if (!s) fail(409, 'สินค้าหมด');
      if (u.balance < p.price) fail(402, 'ยอดเงินไม่พอ กรุณาเติมเงิน');
      run('UPDATE stock SET sold=1 WHERE id=?', s.id);
      run('UPDATE users SET balance=balance-? WHERE id=?', p.price, me.id);
      run('INSERT INTO orders(user_id,product_id,name,price,data,created) VALUES(?,?,?,?,?,?)', me.id, p.id, p.name, p.price, s.data, now());
      db.exec('COMMIT'); out = { ok: true, data: s.data, balance: u.balance - p.price };
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    return out;
  },
  'GET /api/orders'(req, b, res, me) { if (!me) fail(401, 'กรุณาเข้าสู่ระบบ'); return { orders: q('SELECT id,name,price,data,created FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 100', me.id), topups: q('SELECT id,amount,ref,status,created FROM topups WHERE user_id=? ORDER BY id DESC LIMIT 50', me.id) }; },
  'POST /api/topup'(req, b, res, me) {
    if (!me) fail(401, 'กรุณาเข้าสู่ระบบ');
    const a = +b.amount, ref = clean(b.ref).slice(0, 100);
    if (!(a >= 10 && a <= 50000)) fail(400, 'ยอดเติมต้อง 10–50,000 บาท');
    if (!ref) fail(400, 'กรอกเลขอ้างอิงการโอน');
    run('INSERT INTO topups(user_id,amount,ref,created) VALUES(?,?,?,?)', me.id, a, ref, now());
    return { ok: true };
  },
  // ---- แอดมิน ----
  'GET /api/admin/topups'(req, b, res, me) { admin(me); return { topups: q("SELECT t.*,u.username FROM topups t JOIN users u ON u.id=t.user_id WHERE t.status='pending' ORDER BY t.id") }; },
  'POST /api/admin/topup'(req, b, res, me) {
    admin(me); const t = one("SELECT * FROM topups WHERE id=? AND status='pending'", +b.id); if (!t) fail(404, 'ไม่พบรายการ');
    if (b.approve) run('UPDATE users SET balance=balance+? WHERE id=?', t.amount, t.user_id);
    run('UPDATE topups SET status=? WHERE id=?', b.approve ? 'approved' : 'rejected', t.id); return { ok: true };
  },
  'POST /api/admin/category'(req, b, res, me) { admin(me); if (!clean(b.name)) fail(400, 'กรอกชื่อหมวดหมู่'); run('INSERT INTO categories(name,img) VALUES(?,?)', clean(b.name), clean(b.img)); return { ok: true }; },
  'POST /api/admin/product'(req, b, res, me) {
    admin(me); if (!clean(b.name) || !(+b.price >= 0)) fail(400, 'ข้อมูลสินค้าไม่ครบ');
    run('INSERT INTO products(name,price,img,category_id) VALUES(?,?,?,?)', clean(b.name), +b.price, clean(b.img), +b.category_id || null); return { ok: true };
  },
  'POST /api/admin/stock'(req, b, res, me) {
    admin(me); if (!one('SELECT 1 FROM products WHERE id=?', +b.product_id)) fail(404, 'ไม่พบสินค้า');
    const lines = String(b.lines ?? '').split('\n').map(s => s.trim()).filter(Boolean);
    lines.forEach(l => run('INSERT INTO stock(product_id,data) VALUES(?,?)', +b.product_id, l)); return { ok: true, added: lines.length };
  },
  'POST /api/admin/balance'(req, b, res, me) { admin(me); run('UPDATE users SET balance=balance+? WHERE username=?', +b.amount, clean(b.username)); return { ok: true }; }
};
const admin = me => { if (!me || me.role !== 'admin') fail(403, 'สำหรับแอดมินเท่านั้น'); };
function startSession(res, uid) {
  const t = crypto.randomBytes(32).toString('hex');
  run('INSERT INTO sessions VALUES(?,?,?)', t, uid, now() + 30 * 864e5);
  res.setHeader('Set-Cookie', `sid=${t}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${30 * 86400}`);
  return { user: pub(one('SELECT * FROM users WHERE id=?', uid)) };
}

const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.webp': 'image/webp' };
http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname.startsWith('/api/')) {
    let body = ''; req.on('data', c => { body += c; if (body.length > 1e5) req.destroy(); });
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.setHeader('X-Content-Type-Options', 'nosniff');
      try {
        const h = routes[req.method + ' ' + url.pathname]; if (!h) fail(404, 'ไม่พบ API');
        if (req.method === 'POST' && req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) fail(403, 'origin ไม่ถูกต้อง');
        res.end(JSON.stringify(h(req, body ? JSON.parse(body) : {}, res, session(req))));
      } catch (e) { res.statusCode = e.code || 500; res.end(JSON.stringify({ error: e.code ? e.message : 'เซิร์ฟเวอร์ผิดพลาด' })); if (!e.code) console.error(e); }
    });
    return;
  }
  const f = path.join(__dirname, 'public', url.pathname === '/' ? 'index.html' : path.normalize(url.pathname).replace(/^(\.\.[/\\])+/, ''));
  if (!f.startsWith(path.join(__dirname, 'public')) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.statusCode = 404; return res.end('Not found'); }
  res.setHeader('Content-Type', types[path.extname(f)] || 'application/octet-stream'); fs.createReadStream(f).pipe(res);
}).listen(PORT, () => console.log(`ร้านพร้อมที่ http://localhost:${PORT}  (คนแรกที่สมัครจะเป็นแอดมิน)`));
