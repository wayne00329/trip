import { DurableObject } from 'cloudflare:workers';
import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { Buffer } from 'node:buffer';
import editorPage from './index.html';
import loginPage from './login.html';
import { SECURITY_HEADERS, SESSION_SECONDS, TOKEN_PATTERN } from './security.mjs';

const COOKIE = '__Host-family-trip';
const MAX_FORM_BYTES = 4096;
const INVITATION_VALID_MS = 7 * 24 * 60 * 60 * 1000;
const digest = value => createHash('sha256').update(value).digest('hex');

function getOwnerAccount(env) {
  try {
    const account = JSON.parse(env.TRIP_ACCOUNT);
    if (typeof account.name !== 'string' || !account.name || account.name.length > 64 ||
        !TOKEN_PATTERN.test(account.salt) || !/^[a-f0-9]{128}$/.test(account.hash)) return null;
    return account;
  } catch {
    return null;
  }
}

function validAccountFields(name, password) {
  return name.length >= 1 && name.length <= 64 && password.length >= 12 && password.length <= 128;
}

export class TripAuth extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.db = ctx.storage.sql;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY, account_version TEXT NOT NULL, expires_at INTEGER NOT NULL,
        account_name TEXT
      );
      CREATE TABLE IF NOT EXISTS login_attempts (
        bucket TEXT PRIMARY KEY, attempts INTEGER NOT NULL, expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS registered_accounts (
        name TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS invitations (
        code_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL
      );
    `);
    const columns = this.db.exec('PRAGMA table_info(sessions)').toArray();
    if (!columns.some(column => column.name === 'account_name')) {
      this.db.exec('ALTER TABLE sessions ADD COLUMN account_name TEXT');
    }
  }

  #countAttempt(bucket, limit, expiresAt, now) {
    const existing = this.db.exec('SELECT attempts, expires_at FROM login_attempts WHERE bucket = ?', bucket).toArray()[0];
    if (existing && existing.expires_at > now && existing.attempts >= limit) return false;
    if (existing && existing.expires_at > now) {
      this.db.exec('UPDATE login_attempts SET attempts = attempts + 1 WHERE bucket = ?', bucket);
    } else {
      this.db.exec('INSERT OR REPLACE INTO login_attempts VALUES (?, 1, ?)', bucket, expiresAt);
    }
    return true;
  }

  #accountByName(name) {
    return this.db.exec('SELECT name, salt, hash FROM registered_accounts WHERE name = ?', name).toArray()[0];
  }

  #newSession(account, accountName, previousToken) {
    const now = Date.now();
    this.db.exec('DELETE FROM sessions WHERE expires_at <= ?', now);
    if (previousToken) this.signOut(previousToken);
    const token = randomBytes(32).toString('hex');
    this.db.exec('INSERT INTO sessions (token_hash, account_version, expires_at, account_name) VALUES (?, ?, ?, ?)',
      digest(token), digest(account.hash), now + SESSION_SECONDS * 1000, accountName);
    return token;
  }

  signIn(name, password, source, previousToken) {
    const owner = getOwnerAccount(this.env);
    if (!owner) return { status: 503 };
    const now = Date.now();
    const ip = `ip:${source}`;
    if (!this.#countAttempt(ip, 10, now + 300000, now) ||
        !this.#countAttempt('all', 60, now + 60000, now)) return { status: 429 };
    this.db.exec('DELETE FROM login_attempts WHERE expires_at <= ?', now);
    if (!validAccountFields(name, password)) return { status: 401 };

    const isOwner = name === owner.name;
    const account = isOwner ? owner : this.#accountByName(name);
    const reference = account || owner;
    const candidate = scryptSync(password, reference.salt, 64);
    if (!timingSafeEqual(candidate, Buffer.from(reference.hash, 'hex')) || !account) return { status: 401 };

    this.db.exec('DELETE FROM login_attempts WHERE bucket = ?', ip);
    return { status: 200, token: this.#newSession(account, isOwner ? null : name, previousToken) };
  }

  signOut(token) {
    if (TOKEN_PATTERN.test(token)) this.db.exec('DELETE FROM sessions WHERE token_hash = ?', digest(token));
  }

  sessionAccount(token) {
    if (!TOKEN_PATTERN.test(token)) return null;
    const session = this.db.exec('SELECT account_version, account_name FROM sessions WHERE token_hash = ? AND expires_at > ?',
      digest(token), Date.now()).toArray()[0];
    if (!session) return null;
    const owner = session.account_name === null;
    const account = owner ? getOwnerAccount(this.env) : this.#accountByName(session.account_name);
    if (!account || session.account_version !== digest(account.hash)) return null;
    const key = owner ? account.name : `registered\0${account.name}`;
    return { owner, scope: digest(key) };
  }

  createInvitation(token) {
    if (!this.sessionAccount(token)?.owner) return null;
    const code = randomBytes(12).toString('hex').toUpperCase();
    const now = Date.now();
    this.db.exec('DELETE FROM invitations WHERE expires_at <= ?', now);
    this.db.exec('INSERT INTO invitations VALUES (?, ?)', digest(code), now + INVITATION_VALID_MS);
    return code.match(/.{4}/g).join('-');
  }

  register(name, password, confirmation, invite, source, previousToken) {
    const owner = getOwnerAccount(this.env);
    if (!owner) return { status: 503 };
    const now = Date.now();
    const ip = `registration:ip:${source}`;
    if (!this.#countAttempt(ip, 8, now + 300000, now) ||
        !this.#countAttempt('registration:all', 30, now + 60000, now)) return { status: 429 };
    this.db.exec('DELETE FROM login_attempts WHERE expires_at <= ?', now);
    if (!validAccountFields(name, password) || /[\u0000-\u001f\u007f]/.test(name)) return { status: 400, problem: 'fields' };
    if (password !== confirmation) return { status: 400, problem: 'confirmation' };
    const code = invite.replace(/[\s-]+/g, '').toUpperCase();
    if (!/^[A-F0-9]{24}$/.test(code)) return { status: 400, problem: 'invite' };

    return this.ctx.storage.transactionSync(() => {
      const codeHash = digest(code);
      const found = this.db.exec('SELECT 1 FROM invitations WHERE code_hash = ? AND expires_at > ?', codeHash, now).toArray()[0];
      if (!found) return { status: 400, problem: 'invite' };
      if (name === owner.name || this.#accountByName(name)) return { status: 409, problem: 'name' };
      const salt = randomBytes(32).toString('hex');
      const hash = scryptSync(password, salt, 64).toString('hex');
      this.db.exec('INSERT INTO registered_accounts VALUES (?, ?, ?)', name, salt, hash);
      this.db.exec('DELETE FROM invitations WHERE code_hash = ?', codeHash);
      this.db.exec('DELETE FROM login_attempts WHERE bucket = ?', ip);
      return { status: 201, token: this.#newSession({ hash }, name, previousToken) };
    });
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

function errorNotice(message) {
  return message ? `<p class="error" role="alert">${message}</p>` : '';
}

function login(status = 200, message = '', { openRegistration = false, registrationError = '', canRegister = true } = {}) {
  const registration = canRegister ? `
    <details id="register" ${openRegistration ? 'open' : ''}>
      <summary>註冊帳號</summary>
      <p>請向家庭帳號持有人取得邀請碼。密碼至少 12 個字元。</p>
      ${errorNotice(registrationError)}
      <form method="post" action="/register">
        <label>邀請碼 <input name="invite" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="40" required></label>
        <label>新帳號 <input name="username" autocomplete="username" maxlength="64" required></label>
        <label>新密碼 <input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="128" required></label>
        <label>確認密碼 <input type="password" name="confirmation" autocomplete="new-password" minlength="12" maxlength="128" required></label>
        <button type="submit">建立帳號</button>
      </form>
    </details>` : '';
  const page = loginPage.replace('<!-- LOGIN_ERROR -->', errorNotice(message)).replace('<!-- REGISTER_FORM -->', registration);
  return response(page, status, {
    'Content-Type': 'text/html; charset=utf-8',
    ...(status === 429 ? { 'Retry-After': '300' } : {})
  });
}

function invitationPage(code = '') {
  const contents = `
    <h1>邀請家人</h1>
    <p>每個邀請碼可註冊一次，7 天後失效。</p>
    ${code ? `<label class="invite-code">邀請碼（請先複製） <input readonly value="${code}" onclick="this.select()"></label>` : ''}
    <form method="post" action="/invitations">
      <button type="submit">產生邀請碼</button>
    </form>
    <a class="account-back" href="/">返回行程</a>
  `;
  const page = loginPage.replace('<title>登入家庭行程</title>', '<title>邀請家人</title>')
    .replace(/<h1>[\s\S]*?<\/main>/, () => `${contents}</main>`);
  return response(page, 200, { 'Content-Type': 'text/html; charset=utf-8' });
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
    if (request.method === 'POST' && (url.pathname === '/login' || url.pathname === '/register')) {
      if (!request.headers.get('Content-Type')?.startsWith('application/x-www-form-urlencoded')) return response('Unsupported format', 415);
      const form = await readForm(request);
      if (!form) return response('Request too large', 413);
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const name = form.get('username')?.trim() || '';
      const password = form.get('password') || '';
      if (url.pathname === '/register') {
        const result = await auth.register(name, password, form.get('confirmation') || '', form.get('invite') || '', ip, session);
        if (result.status === 201) return redirect('/', sessionCookie(result.token, SESSION_SECONDS));
        if (result.status === 503) return login(503, '網站帳號尚未設定。', { canRegister: false });
        const problems = {
          fields: '請輸入帳號和至少 12 個字元的密碼。',
          confirmation: '兩次輸入的密碼不同。',
          invite: '邀請碼無效、已使用或已過期。',
          name: '此帳號名稱已有人使用。'
        };
        const registrationError = result.status === 429 ? '註冊嘗試次數過多，請稍後再試。' : problems[result.problem];
        return login(result.status, '', { openRegistration: true, registrationError });
      }
      const result = await auth.signIn(name, password, ip, session);
      if (result.status === 200) return redirect('/', sessionCookie(result.token, SESSION_SECONDS));
      if (result.status === 429) return login(429, '登入嘗試次數過多，請稍後再試。');
      if (result.status === 503) return login(503, '網站帳號尚未設定。', { canRegister: false });
      return login(401, '帳號或密碼不正確。');
    }
    if (request.method === 'POST' && url.pathname === '/logout') {
      if (session) await auth.signOut(session);
      return redirect('/login', sessionCookie('', 0));
    }
    if (url.pathname === '/invitations' && (request.method === 'GET' || request.method === 'POST')) {
      if (!session) return redirect('/login');
      if (request.method === 'POST') {
        const code = await auth.createInvitation(session);
        return code ? invitationPage(code) : response('Forbidden', 403);
      }
      return (await auth.sessionAccount(session))?.owner ? invitationPage() : response('Forbidden', 403);
    }
    if (request.method !== 'GET') return response('Not found', 404);
    if (url.pathname === '/login') {
      if (session && await auth.sessionAccount(session)) return redirect('/');
      return getOwnerAccount(env) ? login(200, '', { openRegistration: url.searchParams.has('register') })
        : login(503, '網站帳號尚未設定。', { canRegister: false });
    }
    if (url.pathname === '/api/session') {
      return session && await auth.sessionAccount(session) ? response(null, 204) : response('Sign-in required', 401);
    }
    if (url.pathname === '/' || url.pathname === '/index.html') {
      const account = session ? await auth.sessionAccount(session) : null;
      if (!account) return redirect('/login');
      const actions = account.owner ? '<a class="account-action" href="/invitations">邀請家人</a>' : '';
      const page = editorPage.replace('__TRIP_ACCOUNT_SCOPE__', account.scope).replace('<!-- TRIP_ACCOUNT_ACTIONS -->', actions);
      return response(page, 200, { 'Content-Type': 'text/html; charset=utf-8' });
    }
    return response('Not found', 404);
  }
};
