import { DurableObject } from 'cloudflare:workers';
import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';
import editorPage from './index.html';
import loginPage from './login.html';
import { SECURITY_HEADERS, SESSION_SECONDS, TOKEN_PATTERN } from './security.mjs';

const COOKIE = '__Host-family-trip';
const MAX_FORM_BYTES = 4096;
const digest = value => createHash('sha256').update(value).digest('hex');

function getAccount(env) {
  try {
    const account = JSON.parse(env.TRIP_ACCOUNT);
    if (typeof account.name !== 'string' || !account.name || account.name.length > 64 ||
        !TOKEN_PATTERN.test(account.salt) || !/^[a-f0-9]{128}$/.test(account.hash)) return null;
    return account;
  } catch {
    return null;
  }
}

export class TripAuth extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.db = ctx.storage.sql;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY, account_version TEXT NOT NULL, expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS login_attempts (
        bucket TEXT PRIMARY KEY, attempts INTEGER NOT NULL, expires_at INTEGER NOT NULL
      );
    `);
  }

  countAttempt(bucket, limit, expiresAt, now) {
    const existing = this.db.exec('SELECT attempts, expires_at FROM login_attempts WHERE bucket = ?', bucket).toArray()[0];
    if (existing && existing.expires_at > now && existing.attempts >= limit) return false;
    if (existing && existing.expires_at > now) {
      this.db.exec('UPDATE login_attempts SET attempts = attempts + 1 WHERE bucket = ?', bucket);
    } else {
      this.db.exec('INSERT OR REPLACE INTO login_attempts VALUES (?, 1, ?)', bucket, expiresAt);
    }
    return true;
  }

  signIn(name, password, source, previousToken) {
    const account = getAccount(this.env);
    if (!account) return { status: 503 };
    const now = Date.now();
    const ip = `ip:${source}`;
    if (!this.countAttempt(ip, 10, now + 300000, now) ||
        !this.countAttempt('all', 60, now + 60000, now)) return { status: 429 };
    this.db.exec('DELETE FROM login_attempts WHERE expires_at <= ?', now);
    if (!name || name.length > 64 || password.length < 12 || password.length > 128) return { status: 401 };

    const candidate = scryptSync(password, account.salt, 64);
    if (!timingSafeEqual(candidate, Buffer.from(account.hash, 'hex')) || name !== account.name) return { status: 401 };

    this.db.exec('DELETE FROM login_attempts WHERE bucket = ?', ip);
    const accountVersion = digest(account.hash);
    this.db.exec('DELETE FROM sessions WHERE expires_at <= ? OR account_version <> ?', now, accountVersion);
    if (previousToken) this.signOut(previousToken);
    const token = randomBytes(32).toString('hex');
    this.db.exec('INSERT INTO sessions VALUES (?, ?, ?)', digest(token), accountVersion, now + SESSION_SECONDS * 1000);
    return { status: 200, token };
  }

  signOut(token) {
    if (TOKEN_PATTERN.test(token)) this.db.exec('DELETE FROM sessions WHERE token_hash = ?', digest(token));
  }

  sessionValid(token) {
    const account = getAccount(this.env);
    if (!account || !TOKEN_PATTERN.test(token)) return false;
    return this.db.exec('SELECT 1 FROM sessions WHERE token_hash = ? AND account_version = ? AND expires_at > ?',
      digest(token), digest(account.hash), Date.now()).toArray().length > 0;
  }
}

function response(body, status, headers = {}) {
  return new Response(body, { status, headers: { ...SECURITY_HEADERS, ...headers } });
}

function redirect(location, cookie) {
  return response(null, 303, { Location: location, ...(cookie ? { 'Set-Cookie': cookie } : {}) });
}

function sessionCookie(token, age) {
  return `${COOKIE}=${token}; Path=/; Max-Age=${age}; HttpOnly; Secure; SameSite=Lax`;
}

function login(status = 200, message = '') {
  const page = loginPage.replace('<!-- LOGIN_ERROR -->', message ? `<p class="error" role="alert">${message}</p>` : '');
  return response(page, status, {
    'Content-Type': 'text/html; charset=utf-8',
    ...(status === 429 ? { 'Retry-After': '300' } : {})
  });
}

async function readForm(request) {
  const reader = request.body?.getReader();
  if (!reader) return new URLSearchParams();
  const bytes = new Uint8Array(MAX_FORM_BYTES);
  let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return new URLSearchParams(new TextDecoder().decode(bytes.subarray(0, size)));
      if (size + value.length > bytes.length) {
        await reader.cancel();
        return null;
      }
      bytes.set(value, size);
      size += value.length;
    }
  } finally {
    reader.releaseLock();
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cookie = request.headers.get('Cookie')?.split(';').map(entry => entry.trim()).find(entry => entry.startsWith(`${COOKIE}=`));
    const token = cookie?.slice(COOKIE.length + 1);
    const session = TOKEN_PATTERN.test(token || '') ? token : null;
    const auth = env.AUTH.getByName('family-account');

    if (request.method === 'POST' && request.headers.get('Origin') !== url.origin) return response('Forbidden', 403);
    if (request.method === 'POST' && url.pathname === '/login') {
      if (!request.headers.get('Content-Type')?.startsWith('application/x-www-form-urlencoded')) return response('Unsupported format', 415);
      const form = await readForm(request);
      if (!form) return response('Request too large', 413);
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const result = await auth.signIn(form.get('username')?.trim() || '', form.get('password') || '', ip, session);
      if (result.status === 200) return redirect('/', sessionCookie(result.token, SESSION_SECONDS));
      if (result.status === 429) return login(429, '登入嘗試次數過多，請稍後再試。');
      if (result.status === 503) return login(503, '網站帳號尚未設定。');
      return login(401, '帳號或密碼不正確。');
    }
    if (request.method === 'POST' && url.pathname === '/logout') {
      if (session) await auth.signOut(session);
      return redirect('/login', sessionCookie('', 0));
    }
    if (request.method !== 'GET') return response('Not found', 404);
    if (url.pathname === '/login') {
      if (session && await auth.sessionValid(session)) return redirect('/');
      return getAccount(env) ? login() : login(503, '網站帳號尚未設定。');
    }
    if (url.pathname === '/api/session') {
      return session && await auth.sessionValid(session) ? response(null, 204) : response('Sign-in required', 401);
    }
    if (url.pathname === '/' || url.pathname === '/index.html') {
      const account = getAccount(env);
      if (!account || !session || !await auth.sessionValid(session)) return redirect('/login');
      const page = editorPage.replace('__TRIP_ACCOUNT_SCOPE__', digest(account.name));
      return response(page, 200, { 'Content-Type': 'text/html; charset=utf-8' });
    }
    return response('Not found', 404);
  }
};
