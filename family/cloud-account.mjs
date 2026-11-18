import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const directory = process.env.TRIP_DATA_DIR || fileURLToPath(new URL('.data/', import.meta.url));
const db = new DatabaseSync(resolve(directory, 'family.sqlite'), { readOnly: true });
let payload;
try {
  const account = db.prepare('SELECT name, salt, hash FROM account WHERE id = 1').get();
  if (!account) throw new Error('請先在本機登入頁設定帳號和密碼。');
  payload = JSON.stringify({ TRIP_ACCOUNT: JSON.stringify({
    name: account.name,
    salt: account.salt,
    hash: Buffer.from(account.hash).toString('hex')
  }) });
} finally {
  db.close();
}

if (process.stdout.isTTY) throw new Error('請將此指令的輸出透過管線傳給 wrangler secret bulk。');
process.stdout.write(payload);
