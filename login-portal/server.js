#!/usr/bin/env node
// Login portal at login.apps.futrx.xyz.
//
//   1. User clicks "Sign in with Google" → Google OAuth flow
//   2. We get their email from Google, check it against /srv/access.json
//   3. If allowed, we set a session cookie and show their authorized sites
//   4. User clicks a site → we mint a short-lived HS256 JWT and show it
//
// The MCP servers (in each per-site stack) share the same JWT_SECRET and
// validate the JWT's signature + exp + site claim. Same secret, no DB.

'use strict';

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');

// ---- config ------------------------------------------------------------
function required(name) {
  const v = process.env[name];
  if (!v) { console.error(`error: env ${name} is required`); process.exit(1); }
  return v;
}
const GOOGLE_CLIENT_ID     = required('GOOGLE_CLIENT_ID');
const GOOGLE_CLIENT_SECRET = required('GOOGLE_CLIENT_SECRET');
const COOKIE_SECRET        = required('COOKIE_SECRET');
const PUBLIC_URL           = (process.env.PUBLIC_URL || 'https://login.apps.futrx.xyz').replace(/\/$/, '');
const JWT_SECRET_FILE      = process.env.JWT_SECRET_FILE || '/run/jwt-secret';
const ACCESS_FILE          = process.env.ACCESS_FILE || '/srv/access.json';
const MCP_BASE_DOMAIN      = process.env.MCP_BASE_DOMAIN || 'apps.futrx.xyz';
const TOKEN_TTL_SECONDS    = parseInt(process.env.TOKEN_TTL_SECONDS || '86400', 10);
const PORT                 = parseInt(process.env.PORT || '3000', 10);

const JWT_SECRET = fs.readFileSync(JWT_SECRET_FILE, 'utf8').trim();
if (!JWT_SECRET) { console.error('JWT_SECRET file empty'); process.exit(1); }

// ---- helpers -----------------------------------------------------------
function b64url(input) {
  return Buffer.from(input).toString('base64').replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
}
function signJwt(claims) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify(claims));
  const sig = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest());
  return `${header}.${payload}.${sig}`;
}

function setSignedCookie(res, name, value, maxAgeMs) {
  // Encode the payload with base64url so the value contains no `.` —
  // we use `.` as the value/signature delimiter. URL-encoding wasn't
  // sufficient because emails contain literal dots (e.g. .com).
  const enc = Buffer.from(value, 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', COOKIE_SECRET).update(enc).digest('base64url');
  res.append('Set-Cookie',
    `${name}=${enc}.${sig}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.floor(maxAgeMs/1000)}`);
}
function getSignedCookie(req, name) {
  const raw = (req.headers.cookie || '')
    .split(';').map(s => s.trim()).find(s => s.startsWith(name+'='));
  if (!raw) return null;
  const [enc, sig] = raw.slice(name.length+1).split('.');
  if (!enc || !sig) return null;
  const expected = crypto.createHmac('sha256', COOKIE_SECRET).update(enc).digest('base64url');
  try {
    if (sig.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  } catch { return null; }
  return Buffer.from(enc, 'base64url').toString('utf8');
}
function clearCookie(res, name) {
  res.append('Set-Cookie', `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
}

function readAccess() {
  try {
    return JSON.parse(fs.readFileSync(ACCESS_FILE, 'utf8'));
  } catch (e) {
    console.error('access list read failed:', e.message);
    return { users: {}, sites: {} };
  }
}

function getAuthorizedSites(email) {
  const data = readAccess();
  const sites = data?.users?.[email]?.sites;
  return Array.isArray(sites) ? sites : [];
}

function getSiteInfo(slug) {
  const data = readAccess();
  return data?.sites?.[slug] || {};
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// ---- HTML templates ----------------------------------------------------
const PAGE = (title, body) => `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  max-width: 560px; margin: 60px auto; padding: 24px; line-height: 1.5; }
h1 { font-size: 24px; margin: 0 0 8px; }
p { color: #5a6168; margin: 8px 0; }
.card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; margin: 16px 0;
  background: rgba(255,255,255,0.4); }
@media (prefers-color-scheme: dark) {
  body { background:#0f1115; color:#e5e7eb; } p { color:#9aa1ab; }
  .card { background: rgba(255,255,255,0.04); border-color:#2a2f38; }
}
.btn { display: inline-flex; align-items: center; gap: 10px; padding: 12px 20px;
  background: #4285f4; color: white !important; border: none; border-radius: 6px;
  text-decoration: none; font-weight: 500; cursor: pointer; font-size: 14px; }
.btn:hover { background: #3674e0; }
.btn-secondary { background: transparent; color: inherit !important; border: 1px solid #d0d5dc; }
.btn-secondary:hover { background: rgba(0,0,0,0.05); }
ul { padding: 0; list-style: none; }
li { margin: 8px 0; }
.site-btn { display:flex; justify-content:space-between; align-items:center;
  padding: 14px 18px; border: 1px solid #d0d5dc; border-radius: 6px;
  text-decoration: none; color: inherit; font-weight: 500; }
.site-btn:hover { border-color: #4285f4; }
.muted { color: #8b929c; font-size: 13px; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
pre { background: rgba(0,0,0,0.05); padding: 12px; border-radius: 6px; overflow-x: auto; }
@media (prefers-color-scheme: dark) { pre { background: rgba(255,255,255,0.06); } }
.token-box { display:flex; gap: 8px; align-items: stretch; margin: 8px 0 16px; }
.token-box pre { flex: 1; margin: 0; word-break: break-all; white-space: pre-wrap; }
.copy-btn { padding: 0 14px; border: 1px solid #d0d5dc; border-radius: 6px;
  background: transparent; color: inherit; cursor: pointer; font-size: 13px; }
.copy-btn:hover { border-color: #4285f4; }
.footer { margin-top: 32px; font-size: 13px; }
.footer a { color: #4285f4; text-decoration: none; }
details { margin-top: 16px; }
details summary { cursor: pointer; font-size: 14px; color: #4285f4; user-select: none; }
details summary:hover { text-decoration: underline; }
details ul { padding-left: 20px; }
</style>
</head><body>${body}</body></html>`;

const landingHtml = () => PAGE('futrx dev access', `
  <h1>futrx dev access</h1>
  <p>Sign in with your Google account to access the development environments you've been granted.</p>
  <p><a class="btn" href="/auth/google">
    <svg width="18" height="18" viewBox="0 0 18 18" fill="white"><path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844a4.14 4.14 0 0 1-1.796 2.716v2.258h2.908c1.702-1.567 2.684-3.875 2.684-6.615z"/><path d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z"/><path d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332z"/><path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z"/></svg>
    Sign in with Google
  </a></p>
  <p class="footer muted">
    Access is granted by an administrator. If you sign in and don't see your site, contact
    the person who manages this environment.
  </p>
`);

const deniedHtml = (email) => PAGE('Access denied', `
  <h1>No access yet</h1>
  <p>You signed in as <strong>${escapeHtml(email)}</strong>, but this email isn't on the access list.</p>
  <p>Ask an administrator to add your address.</p>
  <p><a class="btn-secondary btn" href="/logout">Sign out</a></p>
`);

const sitesHtml = (email, sites) => PAGE('Pick a site', `
  <h1>Welcome</h1>
  <p>Signed in as <strong>${escapeHtml(email)}</strong>. Pick a site to get a development token.</p>
  <ul>
    ${sites.map(s => `<li><a class="site-btn" href="/token?site=${encodeURIComponent(s)}">
      <span>${escapeHtml(s)}</span><span class="muted">Get token →</span>
    </a></li>`).join('')}
  </ul>
  <p class="footer"><a href="/logout">Sign out</a></p>
`);

function tokenHtml({ email, site, token, expISO, mcpUrl, siteInfo }) {
  const publicUrl = siteInfo.public_url ||
    (siteInfo.domain ? `https://${siteInfo.domain}` : null);
  const repo = siteInfo.repo || null;
  const branch = siteInfo.branch || 'main';

  // Build the message the user pastes into Claude. Self-contained: Claude
  // sees this and has everything it needs to start working.
  const claudeInstructions =
`Connect me to the dev environment for ${site}.

Add this MCP server (no other config needed):
  Name: dev-shell
  URL: ${mcpUrl}
  Bearer token: ${token}

Once connected, you have a Bash tool that runs commands inside a Linux
container as user 'dev'. Default working directory: /home/dev/app.

What you can assume:
- Source code is at /home/dev/app${repo ? ` (clone of ${repo}, branch '${branch}')` : ''}
- Vite dev server is running with HMR; saved file changes appear live at${publicUrl ? `
  ${publicUrl}` : ' the public URL'}
- Git is configured (deploy key, read-write): pull / commit / push all work
- Container has Node 20, npm, git, curl, sudo (passwordless), bash
- You can install more with: sudo apk add <package>
- There is no local filesystem to edit — make all changes via Bash
- Verify visual changes by refreshing${publicUrl ? ` ${publicUrl}` : ' the site URL'}

When in doubt:
- Explore: \`find . -type f | head\`, \`ls\`, \`cat README.md\`
- Locate code: \`grep -r '<keyword>' src/\`
- Check vite picked up an edit: \`docker logs ${site}\` (run from host via ssh
  is needed; otherwise trust HMR and refresh the page)
- Look at running processes: \`ps aux\`

Start by reading the project README and showing me the directory tree.`;

  return PAGE(`Token: ${site}`, `
  <h1>Token for ${escapeHtml(site)}</h1>
  <p class="muted">Issued to ${escapeHtml(email)} · valid until ${escapeHtml(expISO)}</p>

  <div class="card">
    <p><strong>Paste this into Claude</strong></p>
    <p class="muted">Self-contained — Claude will know everything it needs.</p>
    <div class="token-box">
      <pre id="instructions">${escapeHtml(claudeInstructions)}</pre>
      <button class="copy-btn" onclick="copyText('instructions', this)">Copy all</button>
    </div>
  </div>

  <details>
    <summary>Just the token (HS256 JWT)</summary>
    <div class="token-box" style="margin-top:8px">
      <pre id="token">${escapeHtml(token)}</pre>
      <button class="copy-btn" onclick="copyText('token', this)">Copy</button>
    </div>
    <p class="muted">Or, in Claude Code Desktop, export this in your shell and reload the session:</p>
    <pre>export DEV_MCP_TOKEN=${escapeHtml(token)}</pre>
  </details>

  <details>
    <summary>Connection details</summary>
    <ul class="muted" style="line-height:1.7">
      <li>MCP URL: <code>${escapeHtml(mcpUrl)}</code></li>
      ${publicUrl ? `<li>Public URL: <code>${escapeHtml(publicUrl)}</code></li>` : ''}
      ${repo ? `<li>Repo: <code>${escapeHtml(repo)}</code> · branch <code>${escapeHtml(branch)}</code></li>` : ''}
      <li>Valid until: <code>${escapeHtml(expISO)}</code></li>
    </ul>
  </details>

  <p style="margin-top:24px">
    <a class="btn-secondary btn" href="/sites">← Pick another site</a>
    &nbsp;<a class="btn-secondary btn" href="/logout">Sign out</a>
  </p>

  <script>
    function copyText(id, btn) {
      navigator.clipboard.writeText(document.getElementById(id).textContent.trim())
        .then(() => { const t = btn.textContent; btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = t, 1200); });
    }
  </script>
`);
}

// ---- routes ------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);  // honor X-Forwarded-* from Caddy
app.use(express.urlencoded({ extended: false }));

// Request log: method, path, status, duration, any 'session' cookie status.
app.use((req, res, next) => {
  const t0 = Date.now();
  const sessionCookie = getSignedCookie(req, 'session');
  const stateCookie = getSignedCookie(req, 'oauth_state');
  res.on('finish', () => {
    console.error(
      `[${req.method}] ${req.originalUrl} → ${res.statusCode} (${Date.now()-t0}ms) ` +
      `session=${sessionCookie ? `<${sessionCookie}>` : '<none>'} ` +
      `state=${stateCookie ? '<set>' : '<none>'}`
    );
  });
  next();
});

app.get('/health', (_req, res) => res.type('text/plain').send('ok\n'));

app.get('/', (_req, res) => res.send(landingHtml()));

app.get('/auth/google', (_req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  setSignedCookie(res, 'oauth_state', state, 600 * 1000);
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.searchParams.set('client_id', GOOGLE_CLIENT_ID);
  url.searchParams.set('redirect_uri', `${PUBLIC_URL}/auth/callback`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('access_type', 'online');
  url.searchParams.set('prompt', 'select_account');
  url.searchParams.set('state', state);
  res.redirect(url.toString());
});

app.get('/auth/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;
    const cookieState = getSignedCookie(req, 'oauth_state');
    clearCookie(res, 'oauth_state');
    console.error(`[callback] code=${code ? 'yes' : 'no'} state=${state || '-'} cookieState=${cookieState || '-'} googleErr=${error || '-'}`);
    if (error) {
      return res.status(400).type('text/plain').send(`Google returned: ${error}`);
    }
    if (!code || !state || state !== cookieState) {
      return res.status(400).type('text/plain').send(`Bad request (state mismatch). query.state=${state} cookieState=${cookieState}`);
    }
    // Exchange code for tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: `${PUBLIC_URL}/auth/callback`, grant_type: 'authorization_code',
      }),
    });
    if (!tokenRes.ok) {
      const err = await tokenRes.text();
      console.error('token exchange failed:', tokenRes.status, err);
      return res.status(500).type('text/plain').send('OAuth token exchange failed.');
    }
    const tokenData = await tokenRes.json();
    // Get userinfo
    const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    if (!userRes.ok) {
      console.error('userinfo failed:', userRes.status);
      return res.status(500).type('text/plain').send('Could not fetch userinfo.');
    }
    const userInfo = await userRes.json();
    const email = (userInfo.email || '').toLowerCase();
    if (!email || userInfo.email_verified === false) {
      return res.status(403).type('text/plain').send('No verified email from Google.');
    }
    const sites = getAuthorizedSites(email);
    if (sites.length === 0) {
      return res.status(403).send(deniedHtml(email));
    }
    setSignedCookie(res, 'session', email, 24 * 3600 * 1000);
    res.redirect('/sites');
  } catch (e) {
    console.error('callback error:', e);
    res.status(500).type('text/plain').send('Internal error.');
  }
});

app.get('/sites', (req, res) => {
  const email = getSignedCookie(req, 'session');
  if (!email) return res.redirect('/');
  const sites = getAuthorizedSites(email);
  if (sites.length === 0) return res.status(403).send(deniedHtml(email));
  res.send(sitesHtml(email, sites));
});

app.get('/token', (req, res) => {
  const email = getSignedCookie(req, 'session');
  if (!email) return res.redirect('/');
  const site = String(req.query.site || '');
  const sites = getAuthorizedSites(email);
  if (!site || !sites.includes(site)) {
    return res.status(403).type('text/plain').send(`Not authorized for site "${site}".`);
  }
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + TOKEN_TTL_SECONDS;
  const token = signJwt({ iss: PUBLIC_URL, sub: email, email, site, iat, exp });
  const expISO = new Date(exp * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  const mcpUrl = `https://mcp-${site}.${MCP_BASE_DOMAIN}/`;
  const siteInfo = getSiteInfo(site);
  res.send(tokenHtml({ email, site, token, expISO, mcpUrl, siteInfo }));
});

app.get('/logout', (_req, res) => {
  clearCookie(res, 'session');
  res.redirect('/');
});

app.use((req, res) => res.status(404).type('text/plain').send('Not found\n'));

app.listen(PORT, '0.0.0.0', () => {
  console.error(`login portal on :${PORT} (public=${PUBLIC_URL})`);
});
