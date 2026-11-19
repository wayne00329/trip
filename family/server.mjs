import { createHash, randomBytes, scrypt, scryptSync, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { DatabaseSync } from 'node:sqlite';
import { Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { EDITOR_CSP, PDF_SCANNER_CSP, SECURITY_HEADERS, SESSION_SECONDS, TOKEN_PATTERN } from './security.mjs';

const here = name => new URL(name, import.meta.url);
const dataDirectory = resolve(process.env.TRIP_DATA_DIR || fileURLToPath(here('.data/')));
const deriveKey = promisify(scrypt);
const digest = value => createHash('sha256').update(value).digest('hex');
const passwordKeyLength = 64;
const credentialLengthError = '帳號須為 1–64 個字元，密碼須為 12–128 個字元。';
const isLoopback = host => ['127.0.0.1', 'localhost', '::1', '[::1]', '::ffff:127.0.0.1'].includes(host);

mkdirSync(dataDirectory, { recursive: true, mode: 0o700 });
const db = new DatabaseSync(resolve(dataDirectory, 'family.sqlite'));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA busy_timeout = 5000;
  CREATE TABLE IF NOT EXISTS account (
    id INTEGER PRIMARY KEY CHECK (id = 1), name TEXT NOT NULL, salt TEXT NOT NULL, hash BLOB NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL
  );
`);

function validCredentials(user, password) {
  return user.length >= 1 && user.length <= 64 && password.length >= 12 && password.length <= 128;
}

function hashPassword(password) {
  const salt = randomBytes(32).toString('hex');
  return [salt, scryptSync(password, salt, passwordKeyLength)];
}

async function configure() {
  let { TRIP_USERNAME: user, TRIP_PASSWORD: password } = process.env;
  if (user === undefined || password === undefined) {
    if (!process.stdin.isTTY) throw new Error('Run setup in a terminal or supply TRIP_USERNAME and TRIP_PASSWORD.');
    let hideInput = false;
    const output = new Writable({ write(chunk, encoding, done) {
      if (!hideInput) process.stdout.write(chunk, encoding);
      done();
    } });
    const prompt = createInterface({ input: process.stdin, output, terminal: true });
    try {
      user = await prompt.question('家庭帳號：');
      process.stdout.write('家庭密碼（至少 12 個字元，輸入時不顯示）：');
      hideInput = true;
      password = await prompt.question('');
      process.stdout.write('\n再輸入一次家庭密碼：');
      if (password !== await prompt.question('')) throw new Error('兩次輸入的密碼不同。');
    } finally {
      prompt.close();
      process.stdout.write('\n');
    }
  }
  user = user.trim();
  if (!validCredentials(user, password)) throw new Error(credentialLengthError);
  const [salt, hash] = hashPassword(password);
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare('INSERT OR REPLACE INTO account (id, name, salt, hash) VALUES (1, ?, ?, ?)').run(user, salt, hash);
    db.exec('DELETE FROM sessions; COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  console.log('家庭帳密已設定。既有登入已登出。');
}

async function readBody(request, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request.iterator({ destroyOnReturn: false })) {
    size += chunk.length;
    if (size > limit) {
      request.resume();
      throw Object.assign(new Error('Request too large'), { status: 413 });
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function start() {
  const port = Number(process.env.PORT || 4173);
  const host = process.env.TRIP_HOST || '127.0.0.1';
  const publicUrl = new URL(process.env.TRIP_PUBLIC_ORIGIN || `http://127.0.0.1:${port}`);
  if (!['http:', 'https:'].includes(publicUrl.protocol) || publicUrl.href !== `${publicUrl.origin}/` ||
      (publicUrl.protocol !== 'https:' && !isLoopback(publicUrl.hostname))) {
    throw new Error('TRIP_PUBLIC_ORIGIN 必須是 HTTPS 網站網址，或本機測試網址。');
  }
  const secure = publicUrl.protocol === 'https:';
  const browserSetup = !secure && isLoopback(host);
  const hasAccount = db.prepare('SELECT id FROM account WHERE id = 1');
  if (!browserSetup && !hasAccount.get()) {
    throw new Error('請先執行 node server.mjs setup 設定家庭帳密。');
  }
  const createAccount = db.prepare('INSERT OR IGNORE INTO account VALUES (1, ?, ?, ?)');
  const cookieName = secure ? '__Host-family-trip' : 'family-trip';
  const cookie = (token, age) => `${cookieName}=${token}; Path=/; Max-Age=${age}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`;
  const editorPage = readFileSync(here('index.html'), 'utf8');
  const pdfScannerPage = readFileSync(here('pdf-scanner.html'), 'utf8');
  const loginPage = readFileSync(here('login.html'), 'utf8');
  const account = db.prepare('SELECT name, salt, hash FROM account WHERE id = 1');
  const findSession = db.prepare('SELECT 1 FROM sessions WHERE token_hash = ? AND expires_at > ?');
  const createSession = db.prepare('INSERT INTO sessions VALUES (?, ?)');
  const deleteSession = db.prepare('DELETE FROM sessions WHERE token_hash = ?');
  const expireSessions = db.prepare('DELETE FROM sessions WHERE expires_at <= ?');
  const attempts = new Map();
  let checksInFlight = 0;

  function authenticated(request) {
    const entry = request.headers.cookie?.split(';').map(part => part.trim()).find(part => part.startsWith(`${cookieName}=`));
    const token = entry?.slice(cookieName.length + 1);
    if (!token || !TOKEN_PATTERN.test(token)) return null;
    const hash = digest(token);
    return findSession.get(hash, Date.now()) ? hash : null;
  }

  function send(response, status, content, type = 'application/json; charset=utf-8') {
    response.writeHead(status, { 'Content-Type': type });
    response.end(type.startsWith('application/json') ? JSON.stringify(content) : content);
  }

  function redirect(response, location) {
    response.writeHead(303, { Location: location }).end();
  }

  function accountPage(response, status = 200, error = '', setup = false) {
    const content = setup ? loginPage
      .replaceAll('登入家庭行程', '設定家庭帳密')
      .replace('請輸入帳號和密碼以編輯行程。', '第一次使用，請設定網站登入用的帳號和密碼。')
      .replace('action="/login"', 'action="/setup"')
      .replace('autocomplete="current-password"', 'autocomplete="new-password" minlength="12"')
      .replace('<button type="submit">登入</button>', '<label>確認密碼 <input type="password" name="confirmation" autocomplete="new-password" minlength="12" maxlength="128" required></label><button type="submit">建立帳號</button>')
      : loginPage;
    send(response, status, content.replace('<!-- LOGIN_ERROR -->', error ? `<p class="error" role="alert">${error}</p>` : ''), 'text/html; charset=utf-8');
  }

  async function handle(request, response) {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) response.setHeader(name, value);
    const path = new URL(request.url, publicUrl).pathname;
    const method = request.method;
    const session = authenticated(request);
    if ((method === 'POST' || method === 'PUT') && request.headers.origin !== publicUrl.origin) {
      return send(response, 403, { error: 'invalid_origin' });
    }
    const setupFromLocalBrowser = browserSetup && isLoopback(request.socket.remoteAddress) && request.headers.host === publicUrl.host;
    if (path === '/setup' && (method === 'GET' || method === 'POST')) {
      if (!setupFromLocalBrowser) return send(response, 404, { error: 'not_found' });
      if (hasAccount.get()) return redirect(response, '/login');
      if (method === 'GET') return accountPage(response, 200, '', true);
      if (!request.headers['content-type']?.startsWith('application/x-www-form-urlencoded')) return send(response, 415, { error: 'unsupported_type' });
      const form = new URLSearchParams(await readBody(request, 4096));
      const name = form.get('username')?.trim() || '';
      const password = form.get('password') || '';
      if (!validCredentials(name, password)) return accountPage(response, 400, credentialLengthError, true);
      if (password !== form.get('confirmation')) return accountPage(response, 400, '兩次輸入的密碼不同。', true);
      createAccount.run(name, ...hashPassword(password));
      return redirect(response, '/login');
    }
    if (path === '/login' && (method === 'GET' || method === 'POST') && !hasAccount.get()) {
      return setupFromLocalBrowser ? redirect(response, '/setup') : send(response, 503, { error: 'setup_required' });
    }
    if (method === 'GET' && path === '/login') return session ? redirect(response, '/') : accountPage(response);
    if (method === 'POST' && path === '/login') {
      if (!request.headers['content-type']?.startsWith('application/x-www-form-urlencoded')) return send(response, 415, { error: 'unsupported_type' });
      const now = Date.now();
      for (const [key, attempt] of attempts) if (attempt.until <= now) attempts.delete(key);
      const key = request.socket.remoteAddress;
      if ((attempts.get(key)?.count ?? 0) >= 10 || checksInFlight >= 4 || (!attempts.has(key) && attempts.size >= 1000)) {
        response.setHeader('Retry-After', '300');
        return accountPage(response, 429, '登入嘗試次數過多，請稍後再試。');
      }
      const form = new URLSearchParams(await readBody(request, 4096));
      const name = form.get('username')?.trim() || '';
      const password = form.get('password') || '';
      const attempt = attempts.get(key) || { count: 0, until: now + 5 * 60 * 1000 };
      if (attempt.count >= 10 || checksInFlight >= 4 || (!attempts.has(key) && attempts.size >= 1000)) {
        response.setHeader('Retry-After', '300');
        return accountPage(response, 429, '登入嘗試次數過多，請稍後再試。');
      }
      attempt.count += 1;
      attempts.set(key, attempt);
      checksInFlight += 1;
      let match;
      try {
        const details = account.get();
        const candidate = await deriveKey(password, details.salt, passwordKeyLength);
        const stillCurrent = timingSafeEqual(Buffer.from(details.hash), Buffer.from(account.get().hash));
        match = timingSafeEqual(candidate, details.hash) && name === details.name && stillCurrent;
      } finally {
        checksInFlight -= 1;
      }
      if (!match) return accountPage(response, 401, '帳號或密碼不正確。');
      attempts.delete(key);
      if (session) deleteSession.run(session);
      expireSessions.run(now);
      const token = randomBytes(32).toString('hex');
      createSession.run(digest(token), now + SESSION_SECONDS * 1000);
      response.setHeader('Set-Cookie', cookie(token, SESSION_SECONDS));
      return redirect(response, '/');
    }
    if (method === 'POST' && path === '/logout') {
      if (session) deleteSession.run(session);
      response.setHeader('Set-Cookie', cookie('', 0));
      return redirect(response, '/login');
    }
    if (method === 'GET' && path === '/api/session') {
      return session ? response.writeHead(204).end() : send(response, 401, { error: 'sign_in_required' });
    }
    if (method === 'GET' && path === '/pdf-scanner') {
      if (!session) return send(response, 401, { error: 'sign_in_required' });
      response.setHeader('Content-Security-Policy', PDF_SCANNER_CSP);
      response.setHeader('Referrer-Policy', 'no-referrer');
      return send(response, 200, pdfScannerPage, 'text/html; charset=utf-8');
    }
    if (method === 'GET' && (path === '/' || path === '/index.html')) {
      if (!session) return redirect(response, '/login');
      const scope = digest(account.get().name);
      response.setHeader('Content-Security-Policy', EDITOR_CSP);
      return send(response, 200, editorPage.replace('__TRIP_ACCOUNT_SCOPE__', scope), 'text/html; charset=utf-8');
    }
    return send(response, 404, { error: 'not_found' });
  }

  const server = createServer({ requestTimeout: 15000, headersTimeout: 10000 }, (request, response) => {
    handle(request, response).catch(error => {
      const status = error.status || (error instanceof SyntaxError ? 400 : 500);
      if (status === 500) console.error(error);
      if (!response.headersSent && !response.destroyed) send(response, status, { error: 'request_failed' });
    });
  });
  server.listen(port, host, () => console.log(`家庭行程：${publicUrl.origin}`));
}

if (process.argv[2] === 'setup') {
  await configure();
  db.close();
} else {
  start();
}
