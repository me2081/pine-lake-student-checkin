import { Pool } from 'pg';
import { createHash, createHmac, randomBytes, randomInt, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const pool = globalThis.__plscPool || new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 2,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 8000,
  ssl: { rejectUnauthorized: true }
});
globalThis.__plscPool = pool;

const SESSION_COOKIE = '__Host-plsc';
const SESSION_SECONDS = 12 * 60 * 60;

function json(res, status, body, extraHeaders = {}) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  Object.entries(extraHeaders).forEach(([key, value]) => res.setHeader(key, value));
  res.end(JSON.stringify(body));
}
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  try { return new URL(origin).host.toLowerCase() === String(req.headers.host || '').toLowerCase(); }
  catch { return false; }
}
function bodyOf(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return {};
}
function cookieValue(req, name) {
  const cookies = String(req.headers.cookie || '').split(';');
  for (const item of cookies) {
    const at = item.indexOf('=');
    if (at > 0 && item.slice(0, at).trim() === name) return decodeURIComponent(item.slice(at + 1).trim());
  }
  return '';
}
function signature(value) {
  return createHmac('sha256', process.env.CHECKIN_SESSION_SECRET || '').update(value).digest('base64url');
}
function makeSession() {
  const payload = Buffer.from(JSON.stringify({
    exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS,
    nonce: randomBytes(12).toString('hex')
  })).toString('base64url');
  return payload + '.' + signature(payload);
}
function validSession(req) {
  const token = cookieValue(req, SESSION_COOKIE);
  const pieces = token.split('.');
  if (pieces.length !== 2 || !process.env.CHECKIN_SESSION_SECRET) return false;
  const expected = Buffer.from(signature(pieces[0]));
  const supplied = Buffer.from(pieces[1]);
  if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return false;
  try {
    const payload = JSON.parse(Buffer.from(pieces[0], 'base64url').toString('utf8'));
    return Number(payload.exp) > Math.floor(Date.now() / 1000);
  } catch { return false; }
}
function setSession(res) {
  res.setHeader('Set-Cookie', SESSION_COOKIE + '=' + encodeURIComponent(makeSession()) +
    '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=' + SESSION_SECONDS);
}
function clearSession(res) {
  res.setHeader('Set-Cookie', SESSION_COOKIE + '=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
}
function equalText(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && timingSafeEqual(left, right);
}
function clientIpHash(req) {
  const ip = String(req.headers['x-forwarded-for'] || 'unknown').split(',')[0].trim();
  return createHash('sha256').update(ip + ':' + (process.env.CHECKIN_SESSION_SECRET || '')).digest('hex');
}
async function verifyPasscode(passcode) {
  const result = await pool.query('SELECT salt, password_hash FROM public.checkin_admin_credentials WHERE id = 1');
  if (!result.rowCount) return false;
  const row = result.rows[0];
  const derived = await scrypt(String(passcode), Buffer.from(row.salt, 'hex'), 64);
  return equalText(Buffer.from(derived).toString('hex'), row.password_hash);
}
async function isLoginLocked(ipHash) {
  const result = await pool.query(
    'SELECT locked_until FROM public.checkin_login_attempts WHERE ip_hash = $1 AND locked_until > now()',
    [ipHash]
  );
  return result.rowCount > 0;
}
async function recordFailedLogin(ipHash) {
  await pool.query(
    "INSERT INTO public.checkin_login_attempts (ip_hash, attempts, window_started_at) VALUES ($1, 1, now()) " +
    "ON CONFLICT (ip_hash) DO UPDATE SET " +
    "attempts = CASE WHEN public.checkin_login_attempts.window_started_at < now() - interval '15 minutes' THEN 1 ELSE public.checkin_login_attempts.attempts + 1 END, " +
    "window_started_at = CASE WHEN public.checkin_login_attempts.window_started_at < now() - interval '15 minutes' THEN now() ELSE public.checkin_login_attempts.window_started_at END, " +
    "locked_until = CASE WHEN (CASE WHEN public.checkin_login_attempts.window_started_at < now() - interval '15 minutes' THEN 1 ELSE public.checkin_login_attempts.attempts + 1 END) >= 5 THEN now() + interval '15 minutes' ELSE NULL END",
    [ipHash]
  );
}
async function clearLoginFailures(ipHash) {
  await pool.query('DELETE FROM public.checkin_login_attempts WHERE ip_hash = $1', [ipHash]);
}
async function isCodeLocked(ipHash) {
  const result = await pool.query(
    'SELECT locked_until FROM public.checkin_code_attempts WHERE ip_hash = $1 AND locked_until > now()',
    [ipHash]
  );
  return result.rowCount > 0;
}
async function recordCodeFailure(ipHash) {
  await pool.query(
    "INSERT INTO public.checkin_code_attempts (ip_hash, attempts, window_started_at) VALUES ($1, 1, now()) " +
    "ON CONFLICT (ip_hash) DO UPDATE SET " +
    "attempts = CASE WHEN public.checkin_code_attempts.window_started_at < now() - interval '5 minutes' THEN 1 ELSE public.checkin_code_attempts.attempts + 1 END, " +
    "window_started_at = CASE WHEN public.checkin_code_attempts.window_started_at < now() - interval '5 minutes' THEN now() ELSE public.checkin_code_attempts.window_started_at END, " +
    "locked_until = CASE WHEN (CASE WHEN public.checkin_code_attempts.window_started_at < now() - interval '5 minutes' THEN 1 ELSE public.checkin_code_attempts.attempts + 1 END) >= 10 THEN now() + interval '5 minutes' ELSE NULL END",
    [ipHash]
  );
}
async function clearCodeFailures(ipHash) {
  await pool.query('DELETE FROM public.checkin_code_attempts WHERE ip_hash = $1', [ipHash]);
}
async function adminExists() {
  const result = await pool.query('SELECT 1 FROM public.checkin_admin_credentials WHERE id = 1');
  return result.rowCount > 0;
}
function validName(value) {
  return typeof value === 'string' && value.trim().length > 0 && value.trim().length <= 80;
}
function normalizePath(req) {
  const path = new URL(req.url, 'https://local.invalid').pathname;
  return path.replace(/\/+$/, '') || '/';
}

export default async function handler(req, res) {
  if (!process.env.DATABASE_URL || !process.env.CHECKIN_SESSION_SECRET) {
    return json(res, 503, { error: 'Cloud storage is not configured yet.' });
  }
  const path = normalizePath(req);
  try {
    if (path === '/api/state' && req.method === 'GET') {
      return json(res, 200, { ready: true });
    }

    if (path === '/api/checkin' && req.method === 'POST') {
      if (!sameOrigin(req)) return json(res, 403, { error: 'Request origin was not accepted.' });
      const code = String(bodyOf(req).code || '').trim();
      if (! /^[0-9]{3}$/.test(code)) return json(res, 400, { error: 'Enter the 3-digit student code.' });
      const ipHash = clientIpHash(req);
      if (await isCodeLocked(ipHash)) return json(res, 429, { error: 'Too many incorrect codes. Wait 5 minutes or ask an instructor.' });
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const student = await client.query(
          'SELECT id, name FROM public.checkin_students WHERE student_code = $1 AND active = true FOR UPDATE', [code]
        );
        if (!student.rowCount) {
          await client.query('ROLLBACK');
          await recordCodeFailure(ipHash);
          return json(res, 404, { error: 'Code not recognized. Ask an instructor for help.' });
        }
        const latest = await client.query(
          'SELECT action FROM public.checkin_attendance WHERE student_id = $1 ORDER BY occurred_at DESC LIMIT 1',
          [student.rows[0].id]
        );
        const action = latest.rowCount && latest.rows[0].action === 'check-in' ? 'check-out' : 'check-in';
        if (bodyOf(req).preview === true) {
          await client.query('COMMIT');
          return json(res, 200, { name: student.rows[0].name, action });
        }
        if (bodyOf(req).expectedAction !== action) {
          await client.query('ROLLBACK');
          return json(res, 409, { error: 'Attendance changed. Please enter your code again.' });
        }
        await client.query(
          'INSERT INTO public.checkin_attendance (id, student_id, student_name, action) VALUES ($1, $2, $3, $4)',
          [randomBytes(16).toString('hex'), student.rows[0].id, student.rows[0].name, action]
        );
        await client.query('COMMIT');
        try { await clearCodeFailures(ipHash); } catch {}
        return json(res, 200, { action });
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally { client.release(); }
    }

    if (path === '/api/admin/session' && req.method === 'GET') {
      return json(res, 200, { configured: await adminExists(), authenticated: validSession(req) });
    }

    if (path === '/api/admin/setup' && req.method === 'POST') {
      if (!sameOrigin(req)) return json(res, 403, { error: 'Request origin was not accepted.' });
      const data = bodyOf(req);
      const setupCode = String(data.setupCode || '');
      const passcode = String(data.passcode || '');
      if (!process.env.CHECKIN_SETUP_TOKEN || !equalText(setupCode, process.env.CHECKIN_SETUP_TOKEN)) {
        return json(res, 403, { error: 'The one-time setup code is incorrect.' });
      }
      if (passcode.length < 8 || passcode.length > 128) {
        return json(res, 400, { error: 'Choose a passcode with at least 8 characters.' });
      }
      const salt = randomBytes(16);
      const passwordHash = (await scrypt(passcode, salt, 64)).toString('hex');
      const inserted = await pool.query(
        'INSERT INTO public.checkin_admin_credentials (id, salt, password_hash) VALUES (1, $1, $2) ON CONFLICT DO NOTHING RETURNING id',
        [salt.toString('hex'), passwordHash]
      );
      if (!inserted.rowCount) return json(res, 409, { error: 'Admin setup has already been completed.' });
      setSession(res);
      return json(res, 200, { ok: true });
    }

    if (path === '/api/admin/login' && req.method === 'POST') {
      if (!sameOrigin(req)) return json(res, 403, { error: 'Request origin was not accepted.' });
      const ipHash = clientIpHash(req);
      if (await isLoginLocked(ipHash)) return json(res, 429, { error: 'Too many attempts. Try again in 15 minutes.' });
      if (!(await verifyPasscode(bodyOf(req).passcode))) {
        await recordFailedLogin(ipHash);
        return json(res, 401, { error: 'Incorrect passcode.' });
      }
      await clearLoginFailures(ipHash);
      setSession(res);
      return json(res, 200, { ok: true });
    }

    if (path === '/api/admin/logout' && req.method === 'POST') {
      if (!sameOrigin(req)) return json(res, 403, { error: 'Request origin was not accepted.' });
      clearSession(res);
      return json(res, 200, { ok: true });
    }

    if (path.startsWith('/api/admin/')) {
      if (!validSession(req)) return json(res, 401, { error: 'Please unlock Admin first.' });
      if (path === '/api/admin/students' && req.method === 'GET') {
        const result = await pool.query(
          'SELECT s.id, s.name, s.student_code, s.active, s.created_at, ' +
          '(SELECT a.action FROM public.checkin_attendance a WHERE a.student_id = s.id ORDER BY a.occurred_at DESC LIMIT 1) AS latest_action ' +
          'FROM public.checkin_students s ORDER BY lower(s.name), s.name'
        );
        return json(res, 200, { students: result.rows });
      }
      if (path === '/api/admin/students' && req.method === 'POST') {
        if (!sameOrigin(req)) return json(res, 403, { error: 'Request origin was not accepted.' });
        const name = String(bodyOf(req).name || '').trim().replace(/\s+/g, ' ');
        if (!validName(name)) return json(res, 400, { error: 'Enter a student name up to 80 characters.' });
        for (let attempt = 0; attempt < 12; attempt++) {
          const studentCode = String(randomInt(1, 1000)).padStart(3, '0');
          const result = await pool.query(
            'INSERT INTO public.checkin_students (id, name, student_code) VALUES ($1, $2, $3) ' +
            'ON CONFLICT (student_code) DO NOTHING RETURNING id, name, student_code, active, created_at',
            [randomBytes(16).toString('hex'), name, studentCode]
          );
          if (result.rowCount) return json(res, 201, { student: result.rows[0] });
        }
        return json(res, 503, { error: 'Could not generate a unique student code. Try again.' });
      }
      if (path === '/api/admin/export' && req.method === 'GET') {
        const [students, attendance] = await Promise.all([
          pool.query('SELECT id, name, student_code, active, created_at FROM public.checkin_students ORDER BY lower(name), name'),
          pool.query('SELECT student_id, student_name, action, occurred_at FROM public.checkin_attendance ORDER BY occurred_at')
        ]);
        return json(res, 200, { students: students.rows, attendance: attendance.rows });
      }
      const studentId = path === '/api/admin/student' ? new URL(req.url, 'https://local.invalid').searchParams.get('id') : '';
      if (studentId && /^[0-9a-f-]+$/i.test(studentId) && req.method === 'PATCH') {
        if (!sameOrigin(req)) return json(res, 403, { error: 'Request origin was not accepted.' });
        const name = String(bodyOf(req).name || '').trim().replace(/\s+/g, ' ');
        if (!validName(name)) return json(res, 400, { error: 'Enter a student name up to 80 characters.' });
        const result = await pool.query(
          'UPDATE public.checkin_students SET name = $2 WHERE id = $1 AND active = true RETURNING id, name, active, created_at',
          [studentId, name]
        );
        if (!result.rowCount) return json(res, 404, { error: 'Student not found.' });
        await pool.query('UPDATE public.checkin_attendance SET student_name = $2 WHERE student_id = $1', [studentId, name]);
        return json(res, 200, { student: result.rows[0] });
      }
      if (studentId && /^[0-9a-f-]+$/i.test(studentId) && req.method === 'DELETE') {
        if (!sameOrigin(req)) return json(res, 403, { error: 'Request origin was not accepted.' });
        const result = await pool.query(
          'UPDATE public.checkin_students SET active = false WHERE id = $1 AND active = true RETURNING id',
          [studentId]
        );
        if (!result.rowCount) return json(res, 404, { error: 'Student not found.' });
        return json(res, 200, { ok: true });
      }
    }
    return json(res, 404, { error: 'Not found.' });
  } catch (error) {
    if (error && error.code === '23505') return json(res, 409, { error: 'That student is already listed.' });
    console.error('Student check-in API error:', error && error.message ? error.message : 'Unknown error');
    return json(res, 500, { error: 'The server could not complete that request.' });
  }
}
