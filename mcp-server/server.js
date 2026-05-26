#!/usr/bin/env node
// HTTPS MCP server — exposes the Bash tool to remote MCP clients.
//
// Transport: MCP Streamable HTTP (single JSON-RPC POST → single JSON response).
// Auth:      HS256 JWT issued by the login portal; signature, exp, and `site`
//            claim all verified before any tool runs.
// Scope:     One container, named in env MCP_SITE. Every Bash call execs into
//            that container as user `dev`.
//
// Required env:
//   MCP_SITE         docker container name (e.g. "futrx-com")
//   MCP_RESOURCE     this server's canonical URL (e.g. https://mcp-futrx-com.apps.futrx.xyz)
//                    — included in WWW-Authenticate and checked against token `aud`
//   JWT_SECRET_FILE  path to the shared JWT-signing secret (default /run/jwt-secret)
//   AUTH_SERVER_URL  base URL of the authorization server (e.g. https://login.apps.futrx.xyz)
//
// Optional env:
//   PORT              listen port (default 3000)
//   MCP_DEFAULT_CWD   default working dir inside the container (default /home/dev/app)
//   MCP_LABEL         human label included in serverInfo.name

'use strict';
const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

function required(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`error: env ${name} is required`);
    process.exit(1);
  }
  return v;
}

const SITE = required('MCP_SITE');
const RESOURCE = (required('MCP_RESOURCE') || '').replace(/\/$/, '');
const AUTH_SERVER_URL = (required('AUTH_SERVER_URL') || '').replace(/\/$/, '');
const PORT = parseInt(process.env.PORT || '3000', 10);
const DEFAULT_CWD = process.env.MCP_DEFAULT_CWD || '/home/dev/app';
const LABEL = process.env.MCP_LABEL || `dev-shell-${SITE}`;
const JWT_SECRET_FILE = process.env.JWT_SECRET_FILE || '/run/jwt-secret';

const JWT_SECRET = fs.readFileSync(JWT_SECRET_FILE, 'utf8').trim();
if (!JWT_SECRET) {
  console.error('JWT secret file is empty');
  process.exit(1);
}

// ---- JWT verify (HS256 only) ------------------------------------------
function b64urlToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function verifyJwt(token) {
  if (typeof token !== 'string') return { ok: false, reason: 'not a string' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'malformed' };
  const [h, p, s] = parts;

  let header, payload;
  try {
    header = JSON.parse(b64urlToBuf(h).toString('utf8'));
    payload = JSON.parse(b64urlToBuf(p).toString('utf8'));
  } catch {
    return { ok: false, reason: 'undecodable' };
  }
  if (header.alg !== 'HS256' || header.typ !== 'JWT') {
    return { ok: false, reason: 'bad header' };
  }
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest();
  const got = b64urlToBuf(s);
  if (expected.length !== got.length || !crypto.timingSafeEqual(expected, got)) {
    return { ok: false, reason: 'bad signature' };
  }
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) {
    return { ok: false, reason: 'expired' };
  }
  if (payload.site !== SITE) {
    return { ok: false, reason: `wrong site (${payload.site}, expected ${SITE})` };
  }
  // aud check is best-effort: legacy tokens issued via /token (pre-OAuth) don't
  // set `aud`, so accept them. OAuth-issued tokens always set it.
  if (payload.aud) {
    const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    const normalized = auds.map((a) => String(a).replace(/\/$/, ''));
    if (!normalized.includes(RESOURCE)) {
      return { ok: false, reason: `wrong audience (${normalized.join(',')}, expected ${RESOURCE})` };
    }
  }
  return { ok: true, claims: payload };
}

function authHeader(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  return h.slice(7);
}

// ---- docker exec -------------------------------------------------------
function shellQuote(s) {
  return `'${String(s).replace(/'/g, "'\\''")}'`;
}

function dockerExec(command, { cwd = DEFAULT_CWD, timeoutSeconds = 120 } = {}) {
  const remote = `cd ${shellQuote(cwd)} 2>/dev/null; ${command}`;
  const r = spawnSync(
    'docker',
    ['exec', '-i', '-u', 'dev', SITE, '/bin/bash', '-c', remote],
    {
      encoding: 'utf8',
      timeout: timeoutSeconds * 1000,
      maxBuffer: 100 * 1024 * 1024,
    }
  );
  return {
    stdout: r.stdout || '',
    stderr: r.stderr || '',
    exit_code: r.status,
    signal: r.signal || null,
    timed_out: !!(r.error && r.error.code === 'ETIMEDOUT'),
  };
}

// ---- MCP tool surface --------------------------------------------------
const TOOLS = [
  {
    name: 'Bash',
    description:
      `Run any bash command inside the ${SITE} dev container as user 'dev'. ` +
      `Default working directory: ${DEFAULT_CWD} (override via cwd). ` +
      `Returns stdout, stderr, exit_code. Full shell access — pipes, redirects, ` +
      `heredocs, multi-line scripts, sudo, anything.`,
    inputSchema: {
      type: 'object',
      required: ['command'],
      properties: {
        command: { type: 'string', description: 'Shell command(s) to execute. Can be multi-line.' },
        cwd:     { type: 'string', description: `Working directory inside the container (default ${DEFAULT_CWD}).` },
        timeout: { type: 'integer', description: 'Timeout in seconds (default 120, max 900).' },
        description: { type: 'string', description: 'Short description of what this command does (shown to the user).' },
      },
    },
  },
];

function ok(id, result)  { return { jsonrpc: '2.0', id, result }; }
function err(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

function handle(msg, claims) {
  const { id, method, params } = msg;
  if (method === 'initialize') {
    return ok(id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: LABEL, version: '0.4.0' },
    });
  }
  if (method === 'notifications/initialized') return null;
  if (method === 'tools/list') return ok(id, { tools: TOOLS });
  if (method === 'tools/call') {
    if (!params || params.name !== 'Bash') {
      return err(id, -32602, `unknown tool: ${params && params.name}`);
    }
    const a = params.arguments || {};
    if (typeof a.command !== 'string' || !a.command) {
      return err(id, -32602, 'command (string) is required');
    }
    const timeout = Math.min(Math.max(parseInt(a.timeout, 10) || 120, 1), 900);
    console.error(`[exec by ${claims.email}] ${a.command.split('\n')[0].slice(0, 80)}`);
    const r = dockerExec(a.command, { cwd: a.cwd, timeoutSeconds: timeout });
    return ok(id, {
      content: [{ type: 'text', text: JSON.stringify(r, null, 2) }],
      isError: (r.exit_code || 0) !== 0,
    });
  }
  if (method === 'ping') return ok(id, {});
  if (id != null) return err(id, -32601, `method not found: ${method}`);
  return null;
}

// ---- HTTP --------------------------------------------------------------
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, Accept, Mcp-Session-Id');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
}

const server = http.createServer((req, res) => {
  setCors(res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method === 'GET' && (req.url === '/health' || req.url === '/healthz')) {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok\n');
    return;
  }

  // OAuth Protected Resource Metadata (RFC 9728). Tells clients which
  // Authorization Server can issue tokens for this resource. This is what
  // makes the OAuth discovery dance work — MCP clients fetch this URL the
  // first time they get a 401.
  if (req.method === 'GET' && req.url === '/.well-known/oauth-protected-resource') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      resource: RESOURCE,
      authorization_servers: [AUTH_SERVER_URL],
      bearer_methods_supported: ['header'],
      scopes_supported: ['mcp'],
    }));
    return;
  }

  if (req.method !== 'POST' || !['/', '/mcp'].includes(req.url)) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found\n');
    return;
  }

  const token = authHeader(req);
  const v = verifyJwt(token);
  if (!v.ok) {
    // Point the client at our protected-resource metadata; the MCP client
    // follows that to the AS metadata and starts the OAuth dance.
    const challenge =
      `Bearer realm="mcp", ` +
      `resource_metadata="${RESOURCE}/.well-known/oauth-protected-resource", ` +
      `error="invalid_token", error_description="${v.reason}"`;
    res.writeHead(401, { 'content-type': 'application/json', 'www-authenticate': challenge });
    res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32001, message: `Unauthorized: ${v.reason}` } }));
    return;
  }

  let body = '';
  req.setEncoding('utf8');
  req.on('data', (c) => { body += c; if (body.length > 10 * 1024 * 1024) req.destroy(); });
  req.on('end', () => {
    let msg;
    try {
      msg = JSON.parse(body);
    } catch (_) {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' } }));
      return;
    }
    try {
      const response = handle(msg, v.claims);
      if (response === null) {
        res.writeHead(202);
        res.end();
      } else {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(response));
      }
    } catch (e) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: msg && msg.id, error: { code: -32000, message: String(e && e.message || e) } }));
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.error(`MCP server listening on :${PORT}`);
  console.error(`  site=${SITE}`);
  console.error(`  resource=${RESOURCE}`);
  console.error(`  auth_server=${AUTH_SERVER_URL}`);
});
