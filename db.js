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
  const pool = getPool();
  // Each signed-in user's Gmail refresh token (encrypted).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS gmail_users (
      google_sub   TEXT PRIMARY KEY,
      email        TEXT NOT NULL,
      name         TEXT,
      refresh_token TEXT NOT NULL,
      updated_at   TIMESTAMPTZ DEFAULT now()
    )
  `);
  // Per-user profile (name, background, tone, writing style, etc.) as a JSON blob.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_profiles (
      google_sub TEXT PRIMARY KEY,
      data       JSONB NOT NULL DEFAULT '{}',
      updated_at TIMESTAMPTZ DEFAULT now()
    )
  `);
  // Per-user saved contact list as a JSON array.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_contacts (
      google_sub TEXT PRIMARY KEY,
      data       JSONB NOT NULL DEFAULT '[]',
      updated_at TIMESTAMPTZ DEFAULT now()
    )
  `);
  // One row per email actually sent, so we can show sent history / avoid double-emailing.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sent_emails (
      id         BIGSERIAL PRIMARY KEY,
      google_sub TEXT NOT NULL,
      to_email   TEXT NOT NULL,
      to_name    TEXT,
      company    TEXT,
      subject    TEXT,
      sent_at    TIMESTAMPTZ DEFAULT now()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_sent_emails_sub ON sent_emails (google_sub, sent_at DESC)`);
}

// ── Per-user profile ──────────────────────────────────────────────
async function getProfile(sub) {
  const r = await getPool().query('SELECT data FROM user_profiles WHERE google_sub = $1', [sub]);
  return r.rows.length ? r.rows[0].data : null;
}
async function saveProfile(sub, data) {
  await getPool().query(
    `INSERT INTO user_profiles (google_sub, data, updated_at) VALUES ($1, $2::jsonb, now())
     ON CONFLICT (google_sub) DO UPDATE SET data = $2::jsonb, updated_at = now()`,
    [sub, JSON.stringify(data || {})]
  );
}

// ── Per-user contact list ─────────────────────────────────────────
async function getContacts(sub) {
  const r = await getPool().query('SELECT data FROM user_contacts WHERE google_sub = $1', [sub]);
  return r.rows.length ? r.rows[0].data : null;
}
async function saveContacts(sub, data) {
  await getPool().query(
    `INSERT INTO user_contacts (google_sub, data, updated_at) VALUES ($1, $2::jsonb, now())
     ON CONFLICT (google_sub) DO UPDATE SET data = $2::jsonb, updated_at = now()`,
    [sub, JSON.stringify(Array.isArray(data) ? data : [])]
  );
}

// ── Sent-email history ────────────────────────────────────────────
async function addSentEmail(sub, { to_email, to_name, company, subject }) {
  await getPool().query(
    `INSERT INTO sent_emails (google_sub, to_email, to_name, company, subject)
     VALUES ($1, $2, $3, $4, $5)`,
    [sub, to_email, to_name || '', company || '', subject || '']
  );
}
async function getSentHistory(sub, limit = 500) {
  const r = await getPool().query(
    `SELECT to_email, to_name, company, subject, sent_at
     FROM sent_emails WHERE google_sub = $1 ORDER BY sent_at DESC LIMIT $2`,
    [sub, limit]
  );
  return r.rows;
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

module.exports = {
  dbEnabled, initDb, saveUser, getUserRefreshToken,
  getProfile, saveProfile,
  getContacts, saveContacts,
  addSentEmail, getSentHistory,
};
