const { createClient } = require('@libsql/client');
const crypto = require('crypto');

const db = createClient({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN });
const ADMIN_USER = process.env.ADMIN_USER || 'Admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'Password@5848';
const SECRET = process.env.AUTH_SECRET || 'gta6::' + ADMIN_PASS;
const START_DATE = '2026-11-19', START_TIME = '13:00'; // booking start: 19 Nov 1 PM
const CONSOLES = ['fat', 'slim'];

const hashPw = (p, salt = crypto.randomBytes(16).toString('hex')) => salt + ':' + crypto.scryptSync(String(p), salt, 32).toString('hex');
const checkPw = (p, stored) => { const [salt, h] = String(stored || 'x:x').split(':'); const a = Buffer.from(hashPw(p, salt).split(':')[1], 'hex'), b = Buffer.from(h || '', 'hex'); return a.length === b.length && crypto.timingSafeEqual(a, b); };

let ready;
function init() {
  return (ready ||= (async () => { await db.batch([
    `CREATE TABLE IF NOT EXISTS slots(id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT NOT NULL, start TEXT NOT NULL, end TEXT NOT NULL, note TEXT DEFAULT '', UNIQUE(date,start))`,
    `CREATE TABLE IF NOT EXISTS bookings(id INTEGER PRIMARY KEY AUTOINCREMENT, slot_id INTEGER NOT NULL, console TEXT NOT NULL, name TEXT NOT NULL, phone TEXT NOT NULL, advance INTEGER DEFAULT 0, received INTEGER DEFAULT 0, notes TEXT DEFAULT '', proof TEXT DEFAULT '', booked_at TEXT, end_slot_id INTEGER, created_at TEXT DEFAULT (datetime('now')))`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_slot_console ON bookings(slot_id, console)`,
    `CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS booking_slots(booking_id INTEGER NOT NULL, slot_id INTEGER NOT NULL, console TEXT NOT NULL, UNIQUE(slot_id, console))`
  ], 'write');
    await db.execute('ALTER TABLE bookings ADD COLUMN end_slot_id INTEGER').catch(() => {}); // older databases
    await db.execute('INSERT OR IGNORE INTO booking_slots(booking_id,slot_id,console) SELECT id,slot_id,console FROM bookings');
    // first run: save the admin login (from env) into the database, password stored hashed
    if (!(await q('SELECT COUNT(*) c FROM admins'))[0].c) await db.execute({ sql: 'INSERT INTO admins(username,pass_hash) VALUES(?,?)', args: [ADMIN_USER, hashPw(ADMIN_PASS)] });
  })().catch(e => { ready = null; throw e; }));
}

const rows = r => r.rows.map(x => Object.fromEntries(r.columns.map(c => [c, x[c]])));
const q = async (sql, args = []) => rows(await db.execute({ sql, args }));
const str = (v, n = 300) => String(v ?? '').trim().slice(0, n);
const safeEq = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(String(a)).digest(), crypto.createHash('sha256').update(String(b)).digest());
const sign = p => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
function makeToken(u) { const p = Buffer.from(JSON.stringify({ exp: Date.now() + 12 * 3600e3, u })).toString('base64url'); return p + '.' + sign(p); }
function authed(req) {
  const [p, s] = (req.headers.authorization || '').replace('Bearer ', '').split('.');
  if (!p || !s) return false;
  const e = sign(p);
  if (s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return false;
  try { const d = JSON.parse(Buffer.from(p, 'base64url').toString()); return d.exp > Date.now() ? d : false; } catch { return false; }
}
const validSlot = (d, s, e) => /^\d{4}-\d\d-\d\d$/.test(d) && /^\d\d:[0-5]\d$/.test(s) && /^\d\d:[0-5]\d$/.test(e) && e > s && (d > START_DATE || (d === START_DATE && s >= START_TIME));
const mins = t => +t.slice(0, 2) * 60 + +t.slice(3);
const hhmm = m => String(Math.floor(m / 60)).padStart(2, '0') + ':' + String(m % 60).padStart(2, '0');
const addDays = (d, n) => { const x = new Date(d + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
const validProof = p => p === '' || (typeof p === 'string' && p.startsWith('data:image/') && p.length < 3.8e6);

const SLOTS_SQL = `SELECT s.id,s.date,s.start,s.end,s.note,(SELECT group_concat(console) FROM booking_slots WHERE slot_id=s.id) taken FROM slots s ORDER BY s.date,s.start`;

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const out = (code, data) => res.status(code).json(data);
  try {
    await init();
    const a = req.query.a, b = req.body && typeof req.body === 'object' ? req.body : {};

    if (a === 'slots') return out(200, { slots: await q(SLOTS_SQL), now: Date.now() });

    if (a === 'login') {
      if (req.method !== 'POST') return out(405, { error: 'POST required' });
      const adm = (await q('SELECT username,pass_hash FROM admins WHERE username=?', [str(b.username, 60)]))[0];
      if (checkPw(b.password, adm?.pass_hash) && adm) return out(200, { token: makeToken(adm.username) });
      return out(401, { error: 'Incorrect username or password' });
    }

    if (!authed(req)) return out(401, { error: 'Please log in again' });

    if (a === 'change_password') {
      const user = authed(req).u, np = String(b.new_password || '');
      const adm = (await q('SELECT pass_hash FROM admins WHERE username=?', [user]))[0];
      if (!adm || !checkPw(b.current_password, adm.pass_hash)) return out(400, { error: 'Current password is incorrect' });
      if (np.length < 8) return out(400, { error: 'New password must be at least 8 characters' });
      await db.execute({ sql: 'UPDATE admins SET pass_hash=? WHERE username=?', args: [hashPw(np), user] });
      return out(200, { ok: true });
    }

    if (a === 'admin_data') {
      const bookings = await q(`SELECT b.id,b.slot_id,COALESCE(b.end_slot_id,b.slot_id) end_slot_id,b.console,b.name,b.phone,b.advance,b.received,b.notes,b.booked_at,b.created_at,(b.proof!='') has_proof,s.date,s.start,COALESCE(e."end",s."end") "end" FROM bookings b JOIN slots s ON s.id=b.slot_id LEFT JOIN slots e ON e.id=b.end_slot_id ORDER BY s.date,s.start`);
      return out(200, { slots: await q(SLOTS_SQL), bookings });
    }

    if (a === 'proof') {
      const r = await q('SELECT proof FROM bookings WHERE id=?', [+req.query.id]);
      return out(200, { proof: r[0]?.proof || '' });
    }

    if (req.method !== 'POST') return out(405, { error: 'POST required' });

    if (a === 'add_slots') {
      // Times can go past midnight: "25:00" means 1:00 AM of the next day. Such slots stay under the day they started.
      const date = str(b.date, 10), note = str(b.note, 100), list = [];
      const from = str(b.from || b.start, 5);
      if (!/^\d\d:[0-5]\d$/.test(from) || !/^\d{4}-\d\d-\d\d$/.test(date)) return out(400, { error: 'Enter a valid date and start time' });
      const f0 = mins(from);
      const total = b.total !== undefined ? Math.round(+b.total * 60) : mins(str(b.to, 5)) - f0;
      if (!(total >= 30) || total > 2880) return out(400, { error: 'Total hours must be between 0.5 and 48' });
      if (b.mode === 'bulk') {
        const dur = Math.round(+b.hours * 60), days = Math.min(Math.max(+b.days || 1, 1), 31), step = Math.max(1, Math.ceil(total / 1440));
        if (!(dur >= 30)) return out(400, { error: 'Enter a valid slot length' });
        for (let d = 0; d < days; d++) for (let m = f0; m + dur <= f0 + total; m += dur) list.push([addDays(date, d * step), hhmm(m), hhmm(m + dur)]);
      } else list.push([date, hhmm(f0), hhmm(f0 + total)]);
      const good = list.filter(s => validSlot(...s));
      if (!good.length) return out(400, { error: 'Slots must start on or after 19 Nov 2026, 1:00 PM, and the end time must be after the start time' });
      // skip slots that overlap an existing slot (also across midnight)
      const absM = (d, t) => Date.UTC(+d.slice(0, 4), +d.slice(5, 7) - 1, +d.slice(8, 10)) / 60000 + mins(t);
      const ex = (await q('SELECT date,start,"end" FROM slots')).map(e => [absM(e.date, e.start), absM(e.date, e.end)]);
      const fresh = good.filter(s => { const x = absM(s[0], s[1]), y = absM(s[0], s[2]); return !ex.some(e => x < e[1] && y > e[0]); });
      let added = 0;
      if (fresh.length) {
        const rs = await db.batch(fresh.map(s => ({ sql: 'INSERT OR IGNORE INTO slots(date,start,end,note) VALUES(?,?,?,?)', args: [...s, note] })), 'write');
        added = rs.reduce((n, r) => n + r.rowsAffected, 0);
      }
      return out(200, { added, skipped: list.length - added });
    }

    if (a === 'del_slot') {
      const id = +b.id;
      const n = (await q('SELECT COUNT(*) c FROM booking_slots WHERE slot_id=?', [id]))[0].c;
      if (n) return out(409, { error: 'This slot has a booking. Delete the booking first.' });
      await db.execute({ sql: 'DELETE FROM slots WHERE id=?', args: [id] });
      return out(200, { ok: true });
    }

    if (a === 'book' || a === 'update_booking') {
      const isNew = a === 'book';
      if (!isNew && !(await q('SELECT 1 FROM bookings WHERE id=?', [+b.id])).length) return out(404, { error: 'Booking not found' });
      const f = {};
      f.name = str(b.name, 80);
      f.phone = str(b.phone, 20);
      f.console = str(b.console, 10);
      f.advance = Math.max(0, Math.round(+b.advance || 0));
      f.received = b.received ? 1 : 0;
      f.notes = str(b.notes, 500);
      f.booked_at = str(b.booked_at, 16) || new Date().toISOString().slice(0, 16);
      if (b.proof !== undefined) { if (!validProof(b.proof)) return out(400, { error: 'Invalid photo or file too large' }); f.proof = b.proof; }
      if (!CONSOLES.includes(f.console)) return out(400, { error: 'Choose PS5 Fat or PS5 Slim' });
      if (!f.name) return out(400, { error: 'Enter the customer name' });
      if (f.phone.replace(/\D/g, '').length < 10) return out(400, { error: 'Enter a valid phone number' });
      // a booking can cover several continuous slots (any length, e.g. 2h, 3h, 4h, 5h)
      const startS = (await q('SELECT * FROM slots WHERE id=?', [+b.slot_id]))[0];
      const endS = (await q('SELECT * FROM slots WHERE id=?', [+(b.end_slot_id || b.slot_id)]))[0];
      if (!startS || !endS) return out(400, { error: 'Slot not found' });
      if (startS.date !== endS.date || endS.start < startS.start) return out(400, { error: 'The end slot must be on the same day and not before the start slot' });
      const span = await q('SELECT id,start,"end" FROM slots WHERE date=? AND start>=? AND start<=? ORDER BY start', [startS.date, startS.start, endS.start]);
      for (let k = 1; k < span.length; k++) if (span[k].start !== span[k - 1].end) return out(400, { error: 'The slots in this time range are not continuous' });
      f.slot_id = startS.id; f.end_slot_id = endS.id;
      const k = Object.keys(f);
      const tx = await db.transaction('write');
      try {
        let id;
        if (isNew) {
          const r = await tx.execute({ sql: `INSERT INTO bookings(${k}) VALUES(${k.map(() => '?')})`, args: k.map(x => f[x]) });
          id = Number(r.lastInsertRowid);
        } else {
          id = +b.id;
          await tx.execute({ sql: 'DELETE FROM booking_slots WHERE booking_id=?', args: [id] });
          await tx.execute({ sql: `UPDATE bookings SET ${k.map(x => x + '=?')} WHERE id=?`, args: [...k.map(x => f[x]), id] });
        }
        for (const s of span) await tx.execute({ sql: 'INSERT INTO booking_slots(booking_id,slot_id,console) VALUES(?,?,?)', args: [id, s.id, f.console] });
        await tx.commit();
        return out(200, { id });
      } catch (e) {
        await tx.rollback().catch(() => {});
        if (/UNIQUE/i.test(e.message)) return out(409, { error: 'This PS5 is already booked for part of this time' });
        throw e;
      } finally { tx.close(); }
    }

    if (a === 'del_booking') {
      await db.batch([{ sql: 'DELETE FROM booking_slots WHERE booking_id=?', args: [+b.id] }, { sql: 'DELETE FROM bookings WHERE id=?', args: [+b.id] }], 'write');
      return out(200, { ok: true });
    }

    return out(404, { error: 'Unknown action' });
  } catch (e) {
    console.error(e);
    return out(500, { error: 'Server error: ' + e.message });
  }
};
module.exports.config = { api: { bodyParser: { sizeLimit: '4mb' } } };
