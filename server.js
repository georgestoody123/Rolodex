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
    const { to, subject, body } = req.body || {};
    if (!to || !subject || !body) {
      return res.status(400).json({ error: { message: 'Missing recipient, subject, or body.' } });
    }
    const refreshToken = await db.getUserRefreshToken(req.session.user.sub);
    if (!refreshToken) {
      return res.status(401).json({ error: { message: 'No Gmail authorization on file. Please sign in again.' } });
    }
    const result = await googleHelper.sendEmail({
      refreshToken,
      fromEmail: req.session.user.email,
      to, subject, body,
    });
    res.json({ ok: true, id: result.id });
  } catch (e) {
    console.error('Send failed:', e);
    res.status(500).json({ error: { message: 'Failed to send: ' + (e.message || 'unknown error') } });
  }
});

// Serve the app's static files (index.html, etc.) from /public
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`Network Emailer running at http://localhost:${PORT}`);
  console.log(`Gmail send: ${GOOGLE_ENABLED ? 'ENABLED' : 'disabled (set Google + DB env vars to enable)'}`);
});
