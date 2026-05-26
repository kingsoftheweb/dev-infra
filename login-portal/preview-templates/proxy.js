// Local preview-pane proxy.
// Claude Code Desktop auto-launches this via .claude/launch.json on session
// start. It listens on localhost:8787 and forwards everything (including
// WebSocket upgrades, needed for Vite HMR) to the public dev site at
// __TARGET_HOST__, presenting it as same-origin so the preview pane's
// element-select (Cmd+Shift+S) works.

const http = require('http');
const https = require('https');
const tls = require('tls');

const TARGET_HOST = '__TARGET_HOST__';
const TARGET_ORIGIN = `https://${TARGET_HOST}`;
const PORT = parseInt(process.env.PORT, 10) || 8787;

function rewriteRequestHeaders(reqHeaders) {
  const headers = { ...reqHeaders, host: TARGET_HOST };
  if (headers.referer) {
    headers.referer = headers.referer.replace(/^http:\/\/[^/]+/, TARGET_ORIGIN);
  }
  if (headers.origin) headers.origin = TARGET_ORIGIN;
  return headers;
}

const server = http.createServer((req, res) => {
  const proxyReq = https.request(
    {
      hostname: TARGET_HOST,
      port: 443,
      path: req.url,
      method: req.method,
      headers: rewriteRequestHeaders(req.headers),
    },
    (proxyRes) => {
      const out = { ...proxyRes.headers };
      delete out['content-security-policy'];
      delete out['content-security-policy-report-only'];
      delete out['x-frame-options'];
      if (out.location) {
        out.location = out.location.replace(
          new RegExp('^' + TARGET_ORIGIN.replace(/\./g, '\\.')),
          ''
        );
      }
      if (out['set-cookie']) {
        out['set-cookie'] = out['set-cookie'].map((c) =>
          c
            .replace(/;\s*Domain=[^;]+/gi, '')
            .replace(/;\s*Secure/gi, '')
            .replace(/;\s*SameSite=None/gi, '; SameSite=Lax')
        );
      }
      res.writeHead(proxyRes.statusCode, out);
      proxyRes.pipe(res);
    }
  );

  proxyReq.on('error', (err) => {
    console.error('Proxy HTTP error:', err.message);
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain' });
    }
    res.end(`Proxy error: ${err.message}`);
  });

  req.pipe(proxyReq);
});

// WebSocket / HTTP-Upgrade forwarding (Vite HMR rides on this).
server.on('upgrade', (req, clientSocket, head) => {
  const upstream = tls.connect(
    {
      host: TARGET_HOST,
      port: 443,
      servername: TARGET_HOST,
      ALPNProtocols: ['http/1.1'],
    },
    () => {
      const headers = rewriteRequestHeaders(req.headers);
      const lines = [`${req.method} ${req.url} HTTP/1.1`];
      for (const [k, v] of Object.entries(headers)) {
        if (Array.isArray(v)) {
          for (const vi of v) lines.push(`${k}: ${vi}`);
        } else {
          lines.push(`${k}: ${v}`);
        }
      }
      lines.push('', '');
      upstream.write(lines.join('\r\n'));
      if (head && head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    }
  );
  const onErr = (label) => (err) => {
    console.error(`Proxy WS ${label}:`, err.message);
    try { clientSocket.destroy(); } catch {}
    try { upstream.destroy(); } catch {}
  };
  upstream.on('error', onErr('upstream'));
  clientSocket.on('error', onErr('client'));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(
    `preview-proxy listening on http://localhost:${PORT} → ${TARGET_ORIGIN} (with WebSocket forwarding)`
  );
});
