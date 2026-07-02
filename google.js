// Google OAuth + Gmail send helpers.
//
// Two jobs:
//   1. Sign-in: turn the "Allow" click into the person's identity
//      (email/name) plus a refresh token we can store.
//   2. Send: use that stored refresh token to send an email AS that person
//      through the Gmail API.

const { google } = require('googleapis');

// What we ask each user to grant:
//  - openid/email/profile: so we know who they are (this doubles as login)
//  - gmail.send: permission to send mail on their behalf (restricted scope)
//  - gmail.readonly: read their Sent mail so we can build a contact list from it
const SCOPES = [
  'openid',
  'email',
  'profile',
  'https://www.googleapis.com/auth/gmail.send',
  'https://www.googleapis.com/auth/gmail.readonly',
];

function oauthClient(redirectUri) {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    redirectUri
  );
}

// Build the URL we send the user to so they can approve access.
// access_type=offline + prompt=consent guarantees Google returns a refresh
// token (the long-lived secret) every time, not just on the very first grant.
function authUrl(redirectUri, state) {
  return oauthClient(redirectUri).generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: SCOPES,
    // Add newly-requested scopes to any the user already granted, so existing
    // send-only users keep send access when they approve read access.
    include_granted_scopes: true,
    state,
  });
}

// Exchange the one-time code Google redirected back with for tokens,
// and read the user's identity out of the returned id_token.
async function exchangeCode(redirectUri, code) {
  const client = oauthClient(redirectUri);
  const { tokens } = await client.getToken(code);
  const ticket = await client.verifyIdToken({
    idToken: tokens.id_token,
    audience: process.env.GOOGLE_CLIENT_ID,
  });
  const p = ticket.getPayload();
  return {
    tokens,
    profile: { sub: p.sub, email: p.email, name: p.name || '' },
  };
}

// Build a raw RFC-2822 email and base64url-encode it the way Gmail wants.
// Body is base64-encoded so non-ASCII characters (accents, emoji) survive.
function buildRawMessage({ fromEmail, to, subject, body }) {
  const encodedSubject = /^[\x00-\x7F]*$/.test(subject)
    ? subject
    : '=?UTF-8?B?' + Buffer.from(subject, 'utf8').toString('base64') + '?=';

  const b64Body = Buffer.from(body, 'utf8')
    .toString('base64')
    .replace(/(.{76})/g, '$1\r\n'); // wrap long lines per the spec

  const message = [
    `From: ${fromEmail}`,
    `To: ${to}`,
    `Subject: ${encodedSubject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset="UTF-8"',
    'Content-Transfer-Encoding: base64',
    '',
    b64Body,
  ].join('\r\n');

  return Buffer.from(message)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Send one email as the given user, using their stored refresh token.
async function sendEmail({ refreshToken, fromEmail, to, subject, body }) {
  const client = oauthClient(); // no redirect needed when refreshing
  client.setCredentials({ refresh_token: refreshToken });
  const gmail = google.gmail({ version: 'v1', auth: client });
  const raw = buildRawMessage({ fromEmail, to, subject, body });
  const res = await gmail.users.messages.send({
    userId: 'me',
    requestBody: { raw },
  });
  return res.data;
}

// ── Reading Sent mail to build a contact list ─────────────────────
// Run an async mapper over items with bounded concurrency (keeps us within
// Gmail's rate limits and avoids opening hundreds of requests at once).
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let i = 0;
  async function worker() {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await fn(items[idx], idx);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

function headerValue(headers, name) {
  const h = (headers || []).find(x => x.name.toLowerCase() === name.toLowerCase());
  return h ? h.value : '';
}

// Walk a Gmail message payload and pull out a plain-text body snippet.
function extractBodyText(payload) {
  if (!payload) return '';
  // Prefer a text/plain part; fall back to the message-level snippet handled by caller.
  const stack = [payload];
  while (stack.length) {
    const part = stack.shift();
    if (part.mimeType === 'text/plain' && part.body && part.body.data) {
      try {
        return Buffer.from(part.body.data, 'base64').toString('utf8');
      } catch (e) { /* ignore decode errors */ }
    }
    if (part.parts) stack.push(...part.parts);
  }
  return '';
}

// Turn one raw Gmail message into the compact shape the frontend aggregates.
function extractGmailMessage(data) {
  const headers = (data.payload && data.payload.headers) || [];
  const bodyFull = extractBodyText(data.payload);
  const body = (bodyFull || data.snippet || '').slice(0, 2000);
  return {
    to: headerValue(headers, 'To'),
    cc: headerValue(headers, 'Cc'),
    subject: headerValue(headers, 'Subject'),
    date: headerValue(headers, 'Date'),
    body,
  };
}

// Fetch one page (~100 messages) of the user's Sent folder, with headers +
// a body snippet for each. Returns the parsed messages and a nextPageToken
// (null when there are no more pages — i.e. the whole account has been scanned).
async function listSentPage({ refreshToken, pageToken }) {
  const client = oauthClient();
  client.setCredentials({ refresh_token: refreshToken });
  const gmail = google.gmail({ version: 'v1', auth: client });

  const listRes = await gmail.users.messages.list({
    userId: 'me',
    labelIds: ['SENT'],
    maxResults: 100,
    pageToken: pageToken || undefined,
  });
  const ids = (listRes.data.messages || []).map(m => m.id);

  const messages = await mapLimit(ids, 10, async (id) => {
    const msg = await gmail.users.messages.get({ userId: 'me', id, format: 'full' });
    return extractGmailMessage(msg.data);
  });

  return { messages, nextPageToken: listRes.data.nextPageToken || null };
}

// Ask Google to revoke a token so the app's access is fully cut off.
async function revokeToken(token) {
  const res = await fetch('https://oauth2.googleapis.com/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token }).toString(),
  });
  // Google returns 200 on success; a 400 usually means it was already revoked/expired.
  if (!res.ok && res.status !== 400) {
    throw new Error('Revoke returned ' + res.status);
  }
}

module.exports = { authUrl, exchangeCode, sendEmail, listSentPage, revokeToken };
