// Tiny backend whose only job is to keep your Anthropic API key secret.
//
// The browser-side app (public/index.html) never talks to api.anthropic.com
// directly anymore. Instead it calls POST /api/claude on THIS server, and
// this server attaches the secret API key (read from .env, never sent to
// the browser) before forwarding the request on to Anthropic.
//
// Because this is now meant to be reachable on the internet by more than
// just you, two extra protections are added below:
//   1. A username/password prompt (HTTP Basic Auth) so strangers can't load
//      the site or use your API key at all.
//   2. A rate limit on /api/claude so even a logged-in user can't
//      accidentally (or deliberately) run up a huge API bill.

require('dotenv').config();
const express = require('express');
const basicAuth = require('express-basic-auth');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.ANTHROPIC_API_KEY;
const SITE_USER = process.env.SITE_USER;
const SITE_PASS = process.env.SITE_PASS;

if (!API_KEY) {
  console.error('Missing ANTHROPIC_API_KEY. Copy .env.example to .env and add your key.');
  process.exit(1);
}
if (!SITE_USER || !SITE_PASS) {
  console.error('Missing SITE_USER / SITE_PASS. Set them in .env so the site is password-protected.');
  process.exit(1);
}

// Require a username + password for every request to this app.
// The browser will show its own built-in login popup — no extra UI needed.
app.use(basicAuth({
  users: { [SITE_USER]: SITE_PASS },
  challenge: true,
  realm: 'Network Emailer',
}));

app.use(express.json({ limit: '2mb' }));

// Serve the app's static files (index.html, etc.) from /public
app.use(express.static(path.join(__dirname, 'public')));

// Cap how many AI requests one person can make, so a shared key can't get
// drained by mistake or abuse. Adjust the numbers below to taste.
const claudeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50,                  // 50 requests per hour per logged-in browser/IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { message: 'Rate limit reached. Try again later.' } },
});

// Proxy endpoint: the frontend posts the same body it used to send straight
// to Anthropic, and we just relay it with the secret key attached server-side.
app.post('/api/claude', claudeLimiter, async (req, res) => {
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

app.listen(PORT, () => {
  console.log(`Network Emailer running at http://localhost:${PORT}`);
});
