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

// Templates served by /preview-setup. Read once at startup.
const path = require('path');
const PREVIEW_LAUNCH_JSON = fs.readFileSync(
  path.join(__dirname, 'preview-templates/launch.json'), 'utf8'
);
const PREVIEW_PROXY_JS_TMPL = fs.readFileSync(
  path.join(__dirname, 'preview-templates/proxy.js'), 'utf8'
);

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

// ---- OAuth state -------------------------------------------------------
// Authorization codes — short-lived (5 min), single-use. In-memory map;
// losing them on restart is fine (clients just re-authorize).
const codes = new Map();
function pruneCodes() {
  const now = Date.now();
  for (const [k, v] of codes) if (v.expires_at < now) codes.delete(k);
}
setInterval(pruneCodes, 60 * 1000).unref();

// Registered OAuth clients (DCR). Persisted so a registered Claude client
// stays usable across server restarts.
const CLIENTS_FILE = process.env.CLIENTS_FILE || '/srv/oauth/clients.json';
function loadClients() {
  try { return JSON.parse(fs.readFileSync(CLIENTS_FILE, 'utf8')); }
  catch { return {}; }
}
function saveClients(c) {
  const dir = require('path').dirname(CLIENTS_FILE);
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  fs.writeFileSync(CLIENTS_FILE, JSON.stringify(c, null, 2));
}
function registerClient(meta) {
  const clients = loadClients();
  const client_id = 'c_' + crypto.randomBytes(16).toString('hex');
  clients[client_id] = {
    client_name: typeof meta.client_name === 'string' ? meta.client_name.slice(0, 200) : 'Unknown client',
    redirect_uris: meta.redirect_uris,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    application_type: meta.application_type || 'native',
    registered_at: Math.floor(Date.now() / 1000),
  };
  saveClients(clients);
  return { client_id, ...clients[client_id] };
}
function getClient(client_id) {
  if (typeof client_id !== 'string') return null;
  return loadClients()[client_id] || null;
}

// Map an MCP resource URI back to a site slug.  We canonicalize by host:
// `https://mcp-<slug>.<MCP_BASE_DOMAIN>` → `<slug>`.
function siteFromResource(resourceUri) {
  try {
    const u = new URL(String(resourceUri));
    if (!u.hostname.endsWith('.' + MCP_BASE_DOMAIN) && u.hostname !== MCP_BASE_DOMAIN) return null;
    const m = u.hostname.match(/^mcp-([^.]+)\./);
    return m ? m[1] : null;
  } catch { return null; }
}

// Verify a JWT we issued (signature + exp). Doesn't check claims.
function verifyOurJwt(token) {
  if (typeof token !== 'string') return { ok: false, reason: 'not a string' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'malformed' };
  const [h, p, s] = parts;
  let payload;
  try {
    const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    if (header.alg !== 'HS256') return { ok: false, reason: 'bad alg' };
    payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  } catch { return { ok: false, reason: 'undecodable' }; }
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest();
  const got = Buffer.from(s, 'base64url');
  if (expected.length !== got.length || !crypto.timingSafeEqual(expected, got)) {
    return { ok: false, reason: 'bad signature' };
  }
  if (typeof payload.exp !== 'number' || payload.exp < Math.floor(Date.now()/1000)) {
    return { ok: false, reason: 'expired' };
  }
  return { ok: true, claims: payload };
}

const ACCESS_TOKEN_TTL = parseInt(process.env.ACCESS_TOKEN_TTL || (15 * 60), 10);
const REFRESH_TOKEN_TTL = parseInt(process.env.REFRESH_TOKEN_TTL || (30 * 24 * 3600), 10);

function issueOAuthTokens({ email, site, resource, client_id }) {
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomBytes(12).toString('hex');
  const base = {
    iss: PUBLIC_URL,
    sub: email,
    email,
    aud: resource,
    site,
    scope: 'mcp',
    client_id,
    iat: now,
  };
  const access_token  = signJwt({ ...base, exp: now + ACCESS_TOKEN_TTL,  token_use: 'access',  jti });
  const refresh_token = signJwt({ ...base, exp: now + REFRESH_TOKEN_TTL, token_use: 'refresh', jti });
  return {
    access_token,
    refresh_token,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL,
    scope: 'mcp',
  };
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

  // Self-bootstrapping prompt. Claude sees this on any platform and:
  //   1. Notices it doesn't have mcp__dev-shell__Bash yet → runs the right
  //      setup step for its surface (CLI command if it has shell access,
  //      otherwise instructs the user)
  //   2. After setup + restart, sees the tool → reads the briefing → starts
  //      working on the user's task
  // It's idempotent: pasting it again after the setup step is a no-op for
  // setup and proceeds straight to the briefing.
  const previewSetupUrl = `${PUBLIC_URL}/preview-setup?site=${encodeURIComponent(site)}`;
  const claudePrompt =
`Help me develop ${site}. The dev environment for it lives at:
  ${mcpUrl}

═══════════════════════════════════════════════════════════════════
STEP 1 — Setup (one-time per device)
═══════════════════════════════════════════════════════════════════

(1A) Connect the dev-shell MCP server. Check your tools — if you
already have \`mcp__dev-shell__Bash\`, skip to (1B).

Otherwise:
  • Claude Code (Desktop or CLI) — run this with your Bash tool:
      claude mcp add dev-shell --transport http ${mcpUrl}
  • Claude web (claude.ai) or mobile — tell me to:
      Settings → Connectors → Add custom connector
      URL: ${mcpUrl}

On first use of dev-shell you'll be sent to a browser to sign in
with Google and click "Authorize" — that's the OAuth handshake.

(1B) Wire up the local preview pane (Claude Code Desktop only —
skip if I'm on web or mobile). This makes a live, same-origin view
of the dev site appear in Claude Code's preview pane (Cmd+Shift+P),
with HMR pushing edits through automatically.

Run this in the current project folder using your Bash tool:
      curl -fsSL ${previewSetupUrl} | bash

It drops .claude/launch.json + .claude/proxy.js in this folder,
templated for ${site}. The preview pane auto-starts on next session.

After (1A) + optionally (1B), tell me to restart Claude Code (or
restart the chat on web/mobile) and I'll re-paste this same message.

═══════════════════════════════════════════════════════════════════
STEP 2 — once mcp__dev-shell__Bash is available, here's the context
═══════════════════════════════════════════════════════════════════

You're inside a Linux container as user 'dev', default cwd /home/dev/app.

What you can assume:
- Source: /home/dev/app${repo ? ` (clone of ${repo}, branch '${branch}')` : ''}
- Vite dev server with HMR; saved file edits go live at${publicUrl ? `
  ${publicUrl}` : ' the public URL'}
- Git pull/commit/push work (deploy key, read-write)
- Container has Node 20, npm, git, curl, sudo (passwordless), bash
- Install anything with: sudo apk add <package>
- No local filesystem to edit — all changes via Bash
- Verify visual changes by refreshing${publicUrl ? ` ${publicUrl}` : ' the site URL'}

When in doubt:
- Explore: \`find . -type f | head\`, \`ls\`, \`cat README.md\`
- Locate code: \`grep -r '<keyword>' src/\`
- Look at running processes: \`ps aux\`

Start by reading the README and showing me the project tree, then wait
for my next instruction.`;

  return PAGE(`Connect: ${site}`, `
  <h1>You're in.</h1>
  <p class="muted">Signed in as <strong>${escapeHtml(email)}</strong>. Site: <strong>${escapeHtml(site)}</strong>.</p>

  <div class="card">
    <p style="margin-top:0"><strong>Paste this into Claude.</strong> One message handles connect + setup + briefing.</p>
    <div class="token-box">
      <pre id="prompt">${escapeHtml(claudePrompt)}</pre>
      <button class="copy-btn" onclick="copyText('prompt', this)">Copy</button>
    </div>
    <p class="muted" style="margin-top:0">
      First time on this device, Claude will walk you through one short setup
      step (a CLI command or a Settings tweak), then ask you to restart and
      re-paste. After that, the same paste just works.
    </p>
  </div>

  <details>
    <summary>Just the MCP URL</summary>
    <p class="muted">Use this if you want to add the connector by hand.</p>
    <div class="token-box" style="margin-top:8px">
      <pre id="mcpUrl">${escapeHtml(mcpUrl)}</pre>
      <button class="copy-btn" onclick="copyText('mcpUrl', this)">Copy</button>
    </div>
  </details>

  <details>
    <summary>Manual bearer token (skips OAuth — for one-off scripts)</summary>
    <p class="muted">Lasts until ${escapeHtml(expISO)}. Send as <code>Authorization: Bearer …</code>.</p>
    <div class="token-box" style="margin-top:8px">
      <pre id="token">${escapeHtml(token)}</pre>
      <button class="copy-btn" onclick="copyText('token', this)">Copy</button>
    </div>
  </details>

  <details>
    <summary>Connection details</summary>
    <ul class="muted" style="line-height:1.7">
      <li>MCP URL: <code>${escapeHtml(mcpUrl)}</code></li>
      ${publicUrl ? `<li>Public URL: <code>${escapeHtml(publicUrl)}</code></li>` : ''}
      ${repo ? `<li>Repo: <code>${escapeHtml(repo)}</code> · branch <code>${escapeHtml(branch)}</code></li>` : ''}
      <li>Sign-in valid for the duration of your browser session.</li>
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

// ---- consent UI --------------------------------------------------------
function consentHtml({ email, site, client, siteInfo, params }) {
  const publicUrl = siteInfo.public_url || (siteInfo.domain ? `https://${siteInfo.domain}` : null);
  const repo = siteInfo.repo || null;
  const branch = siteInfo.branch || null;
  // Hidden fields preserve every OAuth param for the POST.
  const hiddenFields = ['response_type','client_id','redirect_uri','code_challenge',
    'code_challenge_method','state','resource','scope']
    .map(k => params[k] != null ? `<input type="hidden" name="${k}" value="${escapeHtml(String(params[k]))}">` : '')
    .join('\n    ');
  return PAGE(`Authorize ${escapeHtml(client.client_name)}`, `
  <h1>Authorize access</h1>
  <p><strong>${escapeHtml(client.client_name || 'An app')}</strong> wants to access the dev environment for
     <strong>${escapeHtml(site)}</strong> on your behalf.</p>

  <div class="card">
    <p class="muted" style="margin:0 0 8px">Signed in as <strong>${escapeHtml(email)}</strong></p>
    <p><strong>This will let it:</strong></p>
    <ul style="line-height:1.7">
      <li>Run any shell command inside the <code>${escapeHtml(site)}</code> container as user <code>dev</code></li>
      <li>Read and modify files at <code>/home/dev/app</code></li>
      ${repo ? `<li>Pull/push to <code>${escapeHtml(repo)}</code> (branch <code>${escapeHtml(branch)}</code>) via the configured deploy key</li>` : ''}
      ${publicUrl ? `<li>Affect what's served at <code>${escapeHtml(publicUrl)}</code></li>` : ''}
    </ul>
    <p class="muted" style="margin-top:14px">Access tokens last 15&nbsp;minutes and refresh automatically.
       You can revoke this app any time by signing out.</p>
  </div>

  <form method="POST" action="/oauth/authorize" style="margin-top:24px">
    ${hiddenFields}
    <button class="btn" name="decision" value="approve" style="background:#34a853">Authorize</button>
    &nbsp;
    <button class="btn btn-secondary" name="decision" value="deny" type="submit">Cancel</button>
  </form>

  <p class="footer"><a href="/logout">Sign out as a different user</a></p>
`);
}

// ---- routes ------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);  // honor X-Forwarded-* from Caddy
app.use(express.urlencoded({ extended: false }));
app.use(express.json());   // for /oauth/register, which posts application/json

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
    // Honor a post-auth redirect (set when /oauth/authorize bounces an
    // unauthenticated user through Google). Must be a same-origin path.
    const after = getSignedCookie(req, 'post_auth_redirect');
    clearCookie(res, 'post_auth_redirect');
    if (after && after.startsWith('/')) return res.redirect(after);
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

// ---- OAuth 2.1 endpoints ----------------------------------------------

// AS metadata (RFC 8414). MCP clients fetch this after seeing the
// resource-metadata pointer in the MCP server's 401 response.
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: PUBLIC_URL,
    authorization_endpoint: `${PUBLIC_URL}/oauth/authorize`,
    token_endpoint: `${PUBLIC_URL}/oauth/token`,
    registration_endpoint: `${PUBLIC_URL}/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    scopes_supported: ['mcp'],
    response_modes_supported: ['query'],
  });
});

// Dynamic Client Registration (RFC 7591). Anyone can register a public
// client — there's no client_secret; security comes from PKCE + the
// user-consent gate in /oauth/authorize.
app.post('/oauth/register', (req, res) => {
  const body = req.body || {};
  if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) {
    return res.status(400).json({ error: 'invalid_redirect_uri', error_description: 'redirect_uris[] required' });
  }
  for (const uri of body.redirect_uris) {
    try {
      const u = new URL(String(uri));
      // Allow http only for loopback (Claude Code uses http://localhost:<port>/callback).
      if (u.protocol === 'https:') continue;
      if (u.protocol === 'http:' && /^(localhost|127\.0\.0\.1|\[::1\])$/.test(u.hostname)) continue;
      return res.status(400).json({ error: 'invalid_redirect_uri', error_description: `disallowed: ${uri}` });
    } catch {
      return res.status(400).json({ error: 'invalid_redirect_uri', error_description: `not a URL: ${uri}` });
    }
  }
  const result = registerClient(body);
  res.status(201).json(result);
});

// Authorization endpoint — renders consent UI after the user is signed in.
app.get('/oauth/authorize', (req, res) => {
  const params = req.query;
  const { response_type, client_id, redirect_uri, code_challenge,
          code_challenge_method, resource } = params;

  if (response_type !== 'code')
    return res.status(400).type('text/plain').send('only response_type=code supported');
  if (!client_id) return res.status(400).type('text/plain').send('client_id required');
  if (!redirect_uri) return res.status(400).type('text/plain').send('redirect_uri required');
  if (!code_challenge) return res.status(400).type('text/plain').send('code_challenge required (PKCE)');
  if ((code_challenge_method || 'plain') !== 'S256')
    return res.status(400).type('text/plain').send('only code_challenge_method=S256 supported');
  if (!resource) return res.status(400).type('text/plain').send('resource parameter required (RFC 8707)');

  const client = getClient(String(client_id));
  if (!client) return res.status(400).type('text/plain').send('unknown client_id');
  if (!client.redirect_uris.includes(String(redirect_uri))) {
    return res.status(400).type('text/plain').send('redirect_uri not registered for this client');
  }

  const site = siteFromResource(resource);
  if (!site) return res.status(400).type('text/plain')
    .send(`cannot determine site from resource: ${resource}`);

  const email = getSignedCookie(req, 'session');
  if (!email) {
    // Park the full /oauth/authorize URL in a cookie so we can resume after Google.
    setSignedCookie(res, 'post_auth_redirect', req.originalUrl, 600 * 1000);
    return res.redirect('/auth/google');
  }

  const sites = getAuthorizedSites(email);
  if (!sites.includes(site)) return res.status(403).send(deniedHtml(email));

  const siteInfo = getSiteInfo(site);
  res.send(consentHtml({ email, site, client, siteInfo, params }));
});

// Authorization decision (consent form POST).
app.post('/oauth/authorize', (req, res) => {
  const body = req.body || {};
  const { response_type, client_id, redirect_uri, code_challenge,
          code_challenge_method, state, resource, decision } = body;

  const email = getSignedCookie(req, 'session');
  if (!email) return res.status(401).type('text/plain').send('not signed in');

  const client = getClient(String(client_id));
  if (!client || !client.redirect_uris.includes(String(redirect_uri))) {
    return res.status(400).type('text/plain').send('bad client_id or redirect_uri');
  }
  const site = siteFromResource(resource);
  if (!site) return res.status(400).type('text/plain').send('bad resource');
  const sites = getAuthorizedSites(email);
  if (!sites.includes(site)) return res.status(403).type('text/plain').send('not authorized');

  const back = new URL(String(redirect_uri));
  if (state) back.searchParams.set('state', String(state));
  if (decision !== 'approve') {
    back.searchParams.set('error', 'access_denied');
    return res.redirect(back.toString());
  }
  if (response_type !== 'code' || !code_challenge || (code_challenge_method || 'plain') !== 'S256') {
    back.searchParams.set('error', 'invalid_request');
    return res.redirect(back.toString());
  }

  const code = crypto.randomBytes(32).toString('base64url');
  codes.set(code, {
    client_id: String(client_id),
    redirect_uri: String(redirect_uri),
    code_challenge: String(code_challenge),
    resource: String(resource).replace(/\/$/, ''),
    email,
    site,
    expires_at: Date.now() + 5 * 60 * 1000,
  });
  back.searchParams.set('code', code);
  res.redirect(back.toString());
});

// Token endpoint — authorization_code grant + refresh_token grant.
app.post('/oauth/token', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const b = req.body || {};
  if (b.grant_type === 'authorization_code') {
    const entry = codes.get(String(b.code));
    if (!entry) return res.status(400).json({ error: 'invalid_grant', error_description: 'unknown or used code' });
    codes.delete(String(b.code));  // single-use
    if (entry.expires_at < Date.now())
      return res.status(400).json({ error: 'invalid_grant', error_description: 'code expired' });
    if (entry.client_id !== String(b.client_id))
      return res.status(400).json({ error: 'invalid_grant', error_description: 'client_id mismatch' });
    if (entry.redirect_uri !== String(b.redirect_uri))
      return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
    if (typeof b.code_verifier !== 'string' || !b.code_verifier)
      return res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier required' });
    const computed = crypto.createHash('sha256').update(b.code_verifier).digest('base64url');
    if (computed !== entry.code_challenge)
      return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
    return res.json(issueOAuthTokens({
      email: entry.email,
      site: entry.site,
      resource: entry.resource,
      client_id: entry.client_id,
    }));
  }
  if (b.grant_type === 'refresh_token') {
    const v = verifyOurJwt(String(b.refresh_token || ''));
    if (!v.ok) return res.status(400).json({ error: 'invalid_grant', error_description: v.reason });
    if (v.claims.token_use !== 'refresh')
      return res.status(400).json({ error: 'invalid_grant', error_description: 'not a refresh token' });
    // Re-check the user still has access (so revoking via access.json takes effect).
    if (!getAuthorizedSites(v.claims.email).includes(v.claims.site))
      return res.status(400).json({ error: 'invalid_grant', error_description: 'access revoked' });
    return res.json(issueOAuthTokens({
      email: v.claims.email,
      site: v.claims.site,
      resource: v.claims.aud,
      client_id: v.claims.client_id,
    }));
  }
  return res.status(400).json({ error: 'unsupported_grant_type' });
});

// Self-installer for the local Claude Code Desktop preview pane.
// Pipe to bash:  curl -fsSL https://login.apps.futrx.xyz/preview-setup?site=X | bash
// Writes .claude/launch.json + .claude/proxy.js into the cwd. The proxy is
// templated with the chosen site's public hostname.
app.get('/preview-setup', (req, res) => {
  const site = String(req.query.site || '').trim();
  const info = getSiteInfo(site);
  if (!info || !info.domain) {
    return res.status(404).type('text/plain').send(`# unknown site: ${site || '<missing>'}\n`);
  }
  const target = info.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const proxyJs = PREVIEW_PROXY_JS_TMPL.replace(/__TARGET_HOST__/g, target);
  res.type('text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.send(`#!/usr/bin/env bash
# Local preview-pane setup for site '${site}' (target: ${target}).
# Generated by ${PUBLIC_URL}/preview-setup?site=${encodeURIComponent(site)}
set -euo pipefail

if [[ -e .claude/proxy.js || -e .claude/launch.json ]]; then
  echo "✗ .claude/proxy.js or .claude/launch.json already exists." >&2
  echo "  Refusing to overwrite. Remove them first if you want to reinstall." >&2
  exit 1
fi

mkdir -p .claude

cat > .claude/launch.json <<'__PREVIEW_LAUNCH_EOF__'
${PREVIEW_LAUNCH_JSON}__PREVIEW_LAUNCH_EOF__

cat > .claude/proxy.js <<'__PREVIEW_PROXY_EOF__'
${proxyJs}__PREVIEW_PROXY_EOF__

echo "✓ Local preview pane wired up for site '${site}'."
echo "  Proxy target:  https://${target}"
echo "  Local URL:     http://localhost:8787/  (after Claude Code starts the preview)"
echo
echo "Next: restart Claude Code Desktop in this folder. The preview pane"
echo "      (Cmd+Shift+P) auto-starts and shows the live dev site."
`);
});

app.get('/logout', (_req, res) => {
  clearCookie(res, 'session');
  res.redirect('/');
});

app.use((req, res) => res.status(404).type('text/plain').send('Not found\n'));

app.listen(PORT, '0.0.0.0', () => {
  console.error(`login portal on :${PORT} (public=${PUBLIC_URL})`);
});
