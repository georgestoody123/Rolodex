# Network Emailer

A tiny local web app + backend. The backend's only job is to keep your
Anthropic API key out of the browser (and out of anyone who opens the HTML
file) while still letting the app do live web search and write emails.

## One-time setup

1. Install [Node.js](https://nodejs.org) (LTS version) if you haven't already.
2. Open a terminal in this folder (`network-emailer-app`).
3. Install dependencies:
   ```
   npm install
   ```
4. Create your `.env` file with your API key:
   - Copy `.env.example` to a new file named `.env`
   - Open `.env` and replace `sk-ant-your-key-here` with your real key from
     https://console.anthropic.com/settings/keys
   - **Never share this file or commit it to git** — it's already excluded
     via `.gitignore`.

## Running the app

```
npm start
```

Then open http://localhost:3000 in your browser. That's it — the app works
exactly like before, but now the "live search" connection banner should go
green for real, because the backend is the one talking to Anthropic (with
your key attached server-side), not the browser.

## How it works

- `public/index.html` — the app itself (same UI/logic as before). All calls
  that used to go to `https://api.anthropic.com/v1/messages` directly now go
  to `/api/claude` on this server instead.
- `server.js` — a small Express server. It serves `index.html` and exposes
  one route, `POST /api/claude`, which takes the request body from the
  browser, attaches your secret `ANTHROPIC_API_KEY` and the required
  `anthropic-version` header, and forwards it to Anthropic. The response is
  passed back to the browser. Your key never leaves the server.
- `.env` — holds your secret key as an environment variable, loaded by
  `dotenv`. This file is git-ignored so it won't accidentally get shared.
