// Database layer: stores each signed-in person's Gmail "refresh token"
// (the long-lived secret that lets us send mail as them) ENCRYPTED at rest.
//
// We use Postgres because Render's free tier has no permanent disk, so a
// plain file would be wiped on every restart/redeploy. The token is encrypted
// with AES-256-GCM using TOKEN_ENCRYPTION_KEY before it ever touches the DB,
// so even someone with database access can't read people's tokens.

const crypto = require('crypto');
const { Pool } = require('pg');

const KEY_HEX = process.env.TOKEN_ENCRYPTION_KEY || '';
const KEY = KEY_HEX ? Buffer.from(KEY_HEX, 'hex') : null;

// True only when everything needed for token storage is configured.
function dbEnabled() {
  return !!process.env.DATABASE_URL && !!KEY && KEY.length === 32;
}

let pool = null;
function getPool() {
  if (!pool) {
    const url = process.env.DATABASE_URL;
    // Render Postgres requires SSL; a local Postgres on localhost does not.
    const isLocal = /localhost|127\.0\.0\.1/.test(url || '');
    pool = new Pool({
      connectionString: url,
      ssl: isLocal ? false : { rejectUnauthorized: false },
    });
  }
  return pool;
}

// ── Encryption helpers (AES-256-GCM) ──────────────────────────────
function encrypt(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Store iv + auth tag + ciphertext together, base64-encoded.
  return Buffer.concat([iv, tag, enc]).toString('base64');
}

function decrypt(b64) {
  const data = Buffer.from(b64, 'base64');
  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const enc = data.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

// ── Table + queries ───────────────────────────────────────────────
async function initDb() {
  await getPool().query(`
    CREATE TABLE IF NOT EXISTS gmail_users (
      google_sub   TEXT PRIMARY KEY,
      email        TEXT NOT NULL,
      name         TEXT,
      refresh_token TEXT NOT NULL,
      updated_at   TIMESTAMPTZ DEFAULT now()
    )
  `);
}

// Insert or update a user's encrypted refresh token, keyed by their Google id.
async function saveUser({ sub, email, name, refreshToken }) {
  const enc = encrypt(refreshToken);
  await getPool().query(
    `INSERT INTO gmail_users (google_sub, email, name, refresh_token, updated_at)
     VALUES ($1, $2, $3, $4, now())
     ON CONFLICT (google_sub)
     DO UPDATE SET email = $2, name = $3, refresh_token = $4, updated_at = now()`,
    [sub, email, name || '', enc]
  );
}

// Return the decrypted refresh token for a user, or null if we don't have one.
async function getUserRefreshToken(sub) {
  const r = await getPool().query(
    'SELECT refresh_token FROM gmail_users WHERE google_sub = $1',
    [sub]
  );
  if (!r.rows.length) return null;
  return decrypt(r.rows[0].refresh_token);
}

module.exports = { dbEnabled, initDb, saveUser, getUserRefreshToken };
