#!/usr/bin/env node
// HTTPS MCP server — exposes the Bash tool to remote MCP clients.
//
// Transport: MCP Streamable HTTP (single JSON-RPC POST → single JSON response).
// Auth:      Bearer token (env MCP_TOKEN, compared in constant time).
// Scope:     One container, named in env MCP_SITE. Every Bash call execs
//            into that container as user `dev`.
//
// Required env:
//   MCP_TOKEN   bearer token; clients send `Authorization: Bearer <token>`
//   MCP_SITE    docker container name (e.g. "futrx-com")
//
// Optional env:
//   PORT              listen port (default 3000)
//   MCP_DEFAULT_CWD   default working dir inside the container (default /home/dev/app)
//   MCP_LABEL         human label included in serverInfo.name (default: dev-shell-${MCP_SITE})

'use strict';
const http = require('http');
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

const TOKEN = required('MCP_TOKEN');
const SITE  = required('MCP_SITE');
const PORT  = parseInt(process.env.PORT || '3000', 10);
const DEFAULT_CWD = process.env.MCP_DEFAULT_CWD || '/home/dev/app';
const LABEL = process.env.MCP_LABEL || `dev-shell-${SITE}`;

const TOKEN_BUF = Buffer.from(`Bearer ${TOKEN}`);

function constantTimeEq(a, b) {
  const ab = Buffer.from(a || '');
  if (ab.length !== b.length) return false;
  return crypto.timingSafeEqual(ab, b);
}

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
        command: {
          type: 'string',
          description: 'Shell command(s) to execute. Can be multi-line.',
        },
        cwd: {
          type: 'string',
          description: `Working directory inside the container (default ${DEFAULT_CWD}).`,
        },
        timeout: {
          type: 'integer',
          description: 'Timeout in seconds (default 120, max 900).',
        },
        description: {
          type: 'string',
          description: 'Short description of what this command does (shown to the user).',
        },
      },
    },
  },
];

function ok(id, result)  { return { jsonrpc: '2.0', id, result }; }
function err(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

function handle(msg) {
  const { id, method, params } = msg;
  if (method === 'initialize') {
    return ok(id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: LABEL, version: '0.3.0' },
    });
  }
  if (method === 'notifications/initialized') return null;  // notification, no response
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

  if (req.method !== 'POST' || !['/', '/mcp'].includes(req.url)) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found\n');
    return;
  }

  if (!constantTimeEq(req.headers.authorization, TOKEN_BUF)) {
    res.writeHead(401, { 'content-type': 'application/json', 'www-authenticate': 'Bearer realm="mcp"' });
    res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32001, message: 'Unauthorized' } }));
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
      const response = handle(msg);
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
  console.error(`MCP server listening on :${PORT} (site=${SITE})`);
});
