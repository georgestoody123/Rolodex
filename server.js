// Backend for the Network Emailer.
//
// Responsibilities:
//   1. Hide the Anthropic API key (proxy /api/claude server-side).
//   2. Let each person sign in with their own Google account and send the
//      emails from their own Gmail (/auth/google, /api/send).
//
// Access control, in plain terms:
//   - If Google sign-in is fully configured, the AI endpoints require the
//     visitor to be signed in with Google. Because the app is in Google
//     "testing" mode, only people you've added as test users can sign in,
//     so only they can use your API key or send mail.
//   - If Google sign-in is NOT configured yet (e.g. running locally), we fall
//     back to the simple shared-password gate so nothing is ever left open.

const path = require('path');
// Load .env from this file's own folder, so the server works no matter which
// directory it's started from.
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const cookieSession = require('cookie-session');
const basicAuth = require('express-basic-auth');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const db = require('./db');
const googleHelper = require('./google');

const app = express();
app.set('trust proxy', 1); // we're behind Render's proxy; trust X-Forwarded-* headers
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.ANTHROPIC_API_KEY;

if (!API_KEY) {
  console.error('Missing ANTHROPIC_API_KEY. Copy .env.example to .env and add your key.');
  process.exit(1);
}

// Gmail sending only turns on when every piece it needs is present.
const GOOGLE_ENABLED = !!(
  process.env.GOOGLE_CLIENT_ID &&
  process.env.GOOGLE_CLIENT_SECRET &&
  process.env.SESSION_SECRET &&
  db.dbEnabled()
);

// Don't advertise the server framework.
app.disable('x-powered-by');

// ── Security headers ──────────────────────────────────────────────
// Set on every response. The CSP allows exactly the external origins this app
// uses (Google Fonts + the cdnjs libraries) and nothing else; connect-src
// 'self' means the page can only make network requests back to this server,
// which blocks data exfiltration even if a script were somehow injected.
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join('; '));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

app.use(express.json({ limit: '2mb' }));
app.use(cookieSession({
  name: 'sess',
  secret: process.env.SESSION_SECRET || 'dev-insecure-secret-change-me',
  maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
}));

// When Google isn't configured, keep the whole site behind the shared password
// so the API key is never exposed. (When Google IS configured, the per-user
// sign-in below is the gate instead.)
if (!GOOGLE_ENABLED && process.env.SITE_USER && process.env.SITE_PASS) {
  app.use(basicAuth({
    users: { [process.env.SITE_USER]: process.env.SITE_PASS },
    challenge: true,
    realm: 'Network Emailer',
  }));
}

// Set up the token table on startup (best-effort; logs if it fails).
if (GOOGLE_ENABLED) {
  db.initDb()
    .then(() => console.log('Database ready (Gmail tokens).'))
    .catch((e) => console.error('Database init failed:', e.message));
}

// The redirect target must match one of the URIs registered in Google Cloud.
// We build it from the request so it works on myrolodex.us, www, or localhost.
function redirectUri(req) {
  return `${req.protocol}://${req.get('host')}/auth/google/callback`;
}

// ── Google sign-in routes ─────────────────────────────────────────
app.get('/auth/google', (req, res) => {
  if (!GOOGLE_ENABLED) return res.status(503).send('Gmail sign-in is not configured yet.');
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  res.redirect(googleHelper.authUrl(redirectUri(req), state));
});

app.get('/auth/google/callback', async (req, res) => {
  if (!GOOGLE_ENABLED) return res.status(503).send('Gmail sign-in is not configured yet.');
  try {
    // Guard against cross-site request forgery: the state must match what we set.
    if (!req.query.code || req.query.state !== req.session.oauthState) {
      return res.status(400).send('Sign-in could not be verified. <a href="/">Back to app</a>');
    }
    const { tokens, profile } = await googleHelper.exchangeCode(redirectUri(req), req.query.code);

    if (tokens.refresh_token) {
      await db.saveUser({
        sub: profile.sub,
        email: profile.email,
        name: profile.name,
        refreshToken: tokens.refresh_token,
      });
    } else {
      // Google only omits the refresh token if the user already granted before.
      const existing = await db.getUserRefreshToken(profile.sub);
      if (!existing) {
        return res.status(400).send(
          'Google did not return send permission. Remove the app at ' +
          'myaccount.google.com/permissions, then sign in again. <a href="/">Back</a>'
        );
      }
    }

    req.session.user = { sub: profile.sub, email: profile.email, name: profile.name };
    res.redirect('/');
  } catch (e) {
    console.error('OAuth callback failed:', e);
    res.status(500).send('Sign-in failed: ' + e.message + ' <a href="/">Back to app</a>');
  }
});

app.post('/auth/logout', (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

// Fully disconnect: revoke Google access, delete ALL of this user's stored data
// (token, profile, contacts, sent history), and end the session.
app.post('/api/disconnect', requireAuth, async (req, res) => {
  const sub = req.session.user.sub;
  try {
    // Best-effort: tell Google to revoke the token so access is truly cut off.
    try {
      const refreshToken = await db.getUserRefreshToken(sub);
      if (refreshToken) await googleHelper.revokeToken(refreshToken);
    } catch (revokeErr) {
      console.warn('Token revoke failed (continuing with deletion):', revokeErr.message);
    }
    await db.deleteAllUserData(sub);
    req.session = null;
    res.json({ ok: true });
  } catch (e) {
    console.error('Disconnect failed:', e);
    res.status(500).json({ error: { message: 'Could not fully delete your data: ' + (e.message || 'unknown') } });
  }
});

// Lets the frontend ask "is sign-in available, and who am I?"
app.get('/api/me', (req, res) => {
  res.json({ googleEnabled: GOOGLE_ENABLED, user: (req.session && req.session.user) || null });
});

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  res.status(401).json({ error: { message: 'Please sign in with Google first.' } });
}

// When Google is on, AI calls require a signed-in user. When it's off, the
// shared-password gate above already protects everything, so allow through.
function gateAI(req, res, next) {
  if (GOOGLE_ENABLED) return requireAuth(req, res, next);
  next();
}

const hourlyLimit = (max) => rateLimit({
  windowMs: 60 * 60 * 1000,
  max,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { message: 'Rate limit reached. Try again later.' } },
});

// ── Anthropic proxy (unchanged behavior, now gated) ───────────────
app.post('/api/claude', gateAI, hourlyLimit(50), async (req, res) => {
  try {
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(req.body),
    });
    const data = await anthropicRes.json();
    res.status(anthropicRes.status).json(data);
  } catch (err) {
    console.error('Error calling Anthropic API:', err);
    res.status(500).json({ error: { message: 'Backend error reaching Anthropic API' } });
  }
});

// ── Send an email through the signed-in user's Gmail ──────────────
app.post('/api/send', requireAuth, hourlyLimit(100), async (req, res) => {
  try {
    const { to, subject, body, html, toName, company } = req.body || {};
    if (!to || !subject || !body) {
      return res.status(400).json({ error: { message: 'Missing recipient, subject, or body.' } });
    }
    const refreshToken = await db.getUserRefreshToken(req.session.user.sub);
    if (!refreshToken) {
      // No token stored — the frontend treats NEED_REAUTH as "offer to sign in again".
      return res.status(401).json({ error: { message: 'NEED_REAUTH' } });
    }
    const result = await googleHelper.sendEmail({
      refreshToken,
      fromEmail: req.session.user.email,
      to, subject, body, html,
    });
    // Record it in the user's sent history (best-effort; don't fail the send if this errors).
    try {
      await db.addSentEmail(req.session.user.sub, { to_email: to, to_name: toName, company, subject });
    } catch (histErr) {
      console.error('Could not record sent email:', histErr.message);
    }
    res.json({ ok: true, id: result.id });
  } catch (e) {
    console.error('Send failed:', e);
    // An expired or revoked Google token surfaces here as "invalid_grant" (in
    // testing mode the refresh token dies ~weekly). Tell the frontend to offer
    // re-sign-in instead of showing a cryptic error.
    const msg = e.message || '';
    if (/invalid_grant|invalid_rapt|expired or revoked|invalid[ _]credentials|no refresh token/i.test(msg)) {
      return res.status(401).json({ error: { message: 'NEED_REAUTH' } });
    }
    res.status(500).json({ error: { message: 'Failed to send: ' + (msg || 'unknown error') } });
  }
});

// ── Scan the signed-in user's Sent mail to build a contact list ───
// The frontend calls this repeatedly, passing back the nextPageToken, until
// nextPageToken is null (the whole account has been scanned).
app.post('/api/import-gmail', requireAuth, hourlyLimit(1000), async (req, res) => {
  try {
    const refreshToken = await db.getUserRefreshToken(req.session.user.sub);
    if (!refreshToken) {
      return res.status(401).json({ error: { message: 'No Gmail authorization on file. Please sign in again.' } });
    }
    const { pageToken } = req.body || {};
    const { messages, nextPageToken } = await googleHelper.listSentPage({ refreshToken, pageToken });
    res.json({ messages, nextPageToken });
  } catch (e) {
    console.error('Gmail import failed:', e.message);
    // A missing read scope surfaces as a 403 / "insufficient" error — tell the
    // frontend to send the user through re-consent to grant read access.
    const msg = e.message || '';
    if (/insufficient|scope|permission|forbidden|403|invalid_grant/i.test(msg)) {
      return res.status(403).json({ error: { message: 'NEED_READ_SCOPE' } });
    }
    res.status(500).json({ error: { message: 'Could not read Gmail: ' + msg } });
  }
});

// Record that the signed-in user accepted the Terms (best-effort consent trail).
app.post('/api/accept-terms', requireAuth, async (req, res) => {
  try {
    await db.setTermsAccepted(req.session.user.sub);
    res.json({ ok: true });
  } catch (e) {
    console.error('Record terms acceptance failed:', e.message);
    res.status(500).json({ error: { message: 'Could not record acceptance.' } });
  }
});

// ── Per-user profile (name, background, tone, writing style) ──────
app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const data = await db.getProfile(req.session.user.sub);
    res.json({ profile: data || null });
  } catch (e) {
    console.error('Load profile failed:', e);
    res.status(500).json({ error: { message: 'Could not load profile.' } });
  }
});
app.put('/api/profile', requireAuth, async (req, res) => {
  try {
    await db.saveProfile(req.session.user.sub, req.body || {});
    res.json({ ok: true });
  } catch (e) {
    console.error('Save profile failed:', e);
    res.status(500).json({ error: { message: 'Could not save profile.' } });
  }
});

// ── Per-user saved contact list ───────────────────────────────────
app.get('/api/contacts', requireAuth, async (req, res) => {
  try {
    const data = await db.getContacts(req.session.user.sub);
    res.json({ contacts: Array.isArray(data) ? data : [] });
  } catch (e) {
    console.error('Load contacts failed:', e);
    res.status(500).json({ error: { message: 'Could not load contacts.' } });
  }
});
app.put('/api/contacts', requireAuth, async (req, res) => {
  try {
    const list = Array.isArray(req.body && req.body.contacts) ? req.body.contacts : [];
    await db.saveContacts(req.session.user.sub, list);
    res.json({ ok: true, count: list.length });
  } catch (e) {
    console.error('Save contacts failed:', e);
    res.status(500).json({ error: { message: 'Could not save contacts.' } });
  }
});

// ── Sent-email history ────────────────────────────────────────────
app.get('/api/history', requireAuth, async (req, res) => {
  try {
    const rows = await db.getSentHistory(req.session.user.sub);
    res.json({ history: rows });
  } catch (e) {
    console.error('Load history failed:', e);
    res.status(500).json({ error: { message: 'Could not load history.' } });
  }
});

// Serve the app's static files (index.html, etc.) from /public
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`Network Emailer running at http://localhost:${PORT}`);
  console.log(`Gmail send: ${GOOGLE_ENABLED ? 'ENABLED' : 'disabled (set Google + DB env vars to enable)'}`);
});
