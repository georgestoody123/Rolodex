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
const SCOPES = [
  'openid',
  'email',
  'profile',
  'https://www.googleapis.com/auth/gmail.send',
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

module.exports = { authUrl, exchangeCode, sendEmail };
