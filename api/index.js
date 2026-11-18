const { createClient } = require('@libsql/client');
const crypto = require('crypto');

const db = createClient({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN });
const ADMIN_USER = process.env.ADMIN_USER || 'Admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'Password@5848';
const SECRET = process.env.AUTH_SECRET || 'gta6::' + ADMIN_PASS;
const START_DATE = '2026-11-19', START_TIME = '13:00'; // booking start: 19 Nov 1 PM
const CONSOLES = ['fat', 'slim'];

let ready;
function init() {
  return (ready ||= db.batch([
    `CREATE TABLE IF NOT EXISTS slots(id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT NOT NULL, start TEXT NOT NULL, end TEXT NOT NULL, note TEXT DEFAULT '', UNIQUE(date,start))`,
    `CREATE TABLE IF NOT EXISTS bookings(id INTEGER PRIMARY KEY AUTOINCREMENT, slot_id INTEGER NOT NULL, console TEXT NOT NULL, name TEXT NOT NULL, phone TEXT NOT NULL, advance INTEGER DEFAULT 0, received INTEGER DEFAULT 0, notes TEXT DEFAULT '', proof TEXT DEFAULT '', booked_at TEXT, created_at TEXT DEFAULT (datetime('now')))`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_slot_console ON bookings(slot_id, console)`
  ], 'write').catch(e => { ready = null; throw e; }));
}

const rows = r => r.rows.map(x => Object.fromEntries(r.columns.map(c => [c, x[c]])));
const q = async (sql, args = []) => rows(await db.execute({ sql, args }));
const str = (v, n = 300) => String(v ?? '').trim().slice(0, n);
const safeEq = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(String(a)).digest(), crypto.createHash('sha256').update(String(b)).digest());
const sign = p => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
function makeToken() { const p = Buffer.from(JSON.stringify({ exp: Date.now() + 12 * 3600e3 })).toString('base64url'); return p + '.' + sign(p); }
function authed(req) {
  const [p, s] = (req.headers.authorization || '').replace('Bearer ', '').split('.');
  if (!p || !s) return false;
  const e = sign(p);
  if (s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return false;
  try { return JSON.parse(Buffer.from(p, 'base64url').toString()).exp > Date.now(); } catch { return false; }
}
const validSlot = (d, s, e) => /^\d{4}-\d\d-\d\d$/.test(d) && /^\d\d:\d\d$/.test(s) && /^\d\d:\d\d$/.test(e) && e > s && (d > START_DATE || (d === START_DATE && s >= START_TIME));
const mins = t => +t.slice(0, 2) * 60 + +t.slice(3);
const hhmm = m => String(Math.floor(m / 60)).padStart(2, '0') + ':' + String(m % 60).padStart(2, '0');
const addDays = (d, n) => { const x = new Date(d + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
const validProof = p => p === '' || (typeof p === 'string' && p.startsWith('data:image/') && p.length < 3.8e6);

const SLOTS_SQL = `SELECT s.id,s.date,s.start,s.end,s.note,(SELECT group_concat(console) FROM bookings WHERE slot_id=s.id) taken FROM slots s ORDER BY s.date,s.start`;

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const out = (code, data) => res.status(code).json(data);
  try {
    await init();
    const a = req.query.a, b = req.body && typeof req.body === 'object' ? req.body : {};

    if (a === 'slots') return out(200, { slots: await q(SLOTS_SQL), now: Date.now() });

    if (a === 'login') {
      if (req.method !== 'POST') return out(405, { error: 'POST chahiye' });
      if (safeEq(b.username, ADMIN_USER) & safeEq(b.password, ADMIN_PASS)) return out(200, { token: makeToken() });
      return out(401, { error: 'Username ya password ghalat hai' });
    }

    if (!authed(req)) return out(401, { error: 'Dobara login karein' });

    if (a === 'admin_data') {
      const bookings = await q(`SELECT b.id,b.slot_id,b.console,b.name,b.phone,b.advance,b.received,b.notes,b.booked_at,b.created_at,(b.proof!='') has_proof,s.date,s.start,s.end FROM bookings b JOIN slots s ON s.id=b.slot_id ORDER BY s.date,s.start`);
      return out(200, { slots: await q(SLOTS_SQL), bookings });
    }

    if (a === 'proof') {
      const r = await q('SELECT proof FROM bookings WHERE id=?', [+req.query.id]);
      return out(200, { proof: r[0]?.proof || '' });
    }

    if (req.method !== 'POST') return out(405, { error: 'POST chahiye' });

    if (a === 'add_slots') {
      const date = str(b.date, 10), note = str(b.note, 100), list = [];
      if (b.mode === 'bulk') {
        const from = str(b.from, 5), to = str(b.to, 5), dur = Math.round(+b.hours * 60), days = Math.min(Math.max(+b.days || 1, 1), 31);
        if (!(dur >= 30) || !/^\d\d:\d\d$/.test(from) || !/^\d\d:\d\d$/.test(to)) return out(400, { error: 'From, to aur duration sahi likhein' });
        for (let d = 0; d < days; d++) for (let m = mins(from); m + dur <= mins(to); m += dur) list.push([addDays(date, d), hhmm(m), hhmm(m + dur)]);
      } else list.push([date, str(b.start, 5), str(b.end, 5)]);
      const good = list.filter(s => validSlot(...s));
      if (!good.length) return out(400, { error: 'Slots 19 Nov 2026 1:00 PM ya uske baad ke hon, aur end time start se baad ho' });
      const rs = await db.batch(good.map(s => ({ sql: 'INSERT OR IGNORE INTO slots(date,start,end,note) VALUES(?,?,?,?)', args: [...s, note] })), 'write');
      const added = rs.reduce((n, r) => n + r.rowsAffected, 0);
      return out(200, { added, skipped: list.length - added });
    }

    if (a === 'del_slot') {
      const id = +b.id;
      const n = (await q('SELECT COUNT(*) c FROM bookings WHERE slot_id=?', [id]))[0].c;
      if (n) return out(409, { error: 'Is slot mein booking hai. Pehle booking delete karein.' });
      await db.execute({ sql: 'DELETE FROM slots WHERE id=?', args: [id] });
      return out(200, { ok: true });
    }

    if (a === 'book' || a === 'update_booking') {
      const isNew = a === 'book';
      const f = {};
      if (isNew || b.slot_id !== undefined) f.slot_id = +b.slot_id;
      if (isNew || b.console !== undefined) f.console = str(b.console, 10);
      if (isNew || b.name !== undefined) f.name = str(b.name, 80);
      if (isNew || b.phone !== undefined) f.phone = str(b.phone, 20);
      if (b.advance !== undefined || isNew) f.advance = Math.max(0, Math.round(+b.advance || 0));
      if (b.received !== undefined || isNew) f.received = b.received ? 1 : 0;
      if (b.notes !== undefined || isNew) f.notes = str(b.notes, 500);
      if (b.booked_at !== undefined || isNew) f.booked_at = str(b.booked_at, 16) || new Date().toISOString().slice(0, 16);
      if (b.proof !== undefined) { if (!validProof(b.proof)) return out(400, { error: 'Photo sahi nahi ya bohat bari hai' }); f.proof = b.proof; }
      if ('console' in f && !CONSOLES.includes(f.console)) return out(400, { error: 'PS5 Fat ya PS5 Slim chunein' });
      if ('name' in f && !f.name) return out(400, { error: 'Customer ka naam likhein' });
      if ('phone' in f && f.phone.replace(/\D/g, '').length < 10) return out(400, { error: 'Phone number sahi likhein' });
      if ('slot_id' in f && !(await q('SELECT 1 FROM slots WHERE id=?', [f.slot_id])).length) return out(400, { error: 'Slot nahi mila' });
      try {
        if (isNew) {
          const k = Object.keys(f);
          const r = await db.execute({ sql: `INSERT INTO bookings(${k}) VALUES(${k.map(() => '?')})`, args: k.map(x => f[x]) });
          return out(200, { id: Number(r.lastInsertRowid) });
        }
        const k = Object.keys(f);
        if (k.length) await db.execute({ sql: `UPDATE bookings SET ${k.map(x => x + '=?')} WHERE id=?`, args: [...k.map(x => f[x]), +b.id] });
        return out(200, { ok: true });
      } catch (e) {
        if (/UNIQUE/i.test(e.message)) return out(409, { error: 'Ye PS5 is slot mein pehle se booked hai' });
        throw e;
      }
    }

    if (a === 'del_booking') {
      await db.execute({ sql: 'DELETE FROM bookings WHERE id=?', args: [+b.id] });
      return out(200, { ok: true });
    }

    return out(404, { error: 'Unknown action' });
  } catch (e) {
    console.error(e);
    return out(500, { error: 'Server error: ' + e.message });
  }
};
module.exports.config = { api: { bodyParser: { sizeLimit: '4mb' } } };
