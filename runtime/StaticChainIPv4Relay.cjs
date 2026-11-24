'use strict';
// Bundled IPv4 Static Chain Relay (127.0.0.1:17902 -> 127.0.0.1:17901 Mihomo upstream)
// Supports env overrides: STATIC_CHAIN_UPSTREAM_PORT, STATIC_CHAIN_LISTEN_PORT
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');

const UPSTREAM_HOST = '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.STATIC_CHAIN_UPSTREAM_PORT || 17901);
const LISTEN_PORT = Number(process.env.STATIC_CHAIN_LISTEN_PORT || 17902);
const cache = new Map();
const pendingDns = new Map();
const stats = { startedAt: new Date().toISOString(), tunnels: 0, active: 0, dnsQueries: 0, errors: 0, lastErrorCode: null };

function recordError(error) { stats.errors++; stats.lastErrorCode = error.code || 'UPSTREAM_ERROR'; }
function coded(code) { const e = new Error(code); e.code = code; return e; }

function openTunnel(address, port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: UPSTREAM_HOST, port: UPSTREAM_PORT });
    let buffer = Buffer.alloc(0);
    let finished = false;
    const fail = (error) => { if (finished) return; finished = true; socket.destroy(); reject(error); };
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) { if (buffer.length > 65536) fail(coded('PROXY_HEADER_TOO_LARGE')); return; }
      const line = buffer.subarray(0, end).toString('latin1').split('\r\n')[0];
      const match = /^HTTP\/\d(?:\.\d)?\s+(\d{3})\b/.exec(line);
      if (!match || match[1] !== '200') { fail(coded('UPSTREAM_CONNECT_REJECTED')); return; }
      finished = true;
      socket.removeListener('data', onData);
      socket.removeListener('error', fail);
      socket.removeListener('timeout', onTimeout);
      socket.removeListener('end', onEnd);
      socket.setTimeout(0);
      socket.setKeepAlive(true, 30000);
      const extra = buffer.subarray(end + 4);
      if (extra.length) socket.unshift(extra);
      resolve(socket);
    };
    const onTimeout = () => fail(coded('UPSTREAM_CONNECT_TIMEOUT'));
    const onEnd = () => fail(coded('UPSTREAM_CONNECT_CLOSED'));
    socket.setTimeout(12000);
    socket.once('timeout', onTimeout);
    socket.once('end', onEnd);
    socket.once('error', fail);
    socket.on('data', onData);
    socket.once('connect', () =>
      socket.write(`CONNECT ${address}:${port} HTTP/1.1\r\nHost: ${address}:${port}\r\nProxy-Connection: Keep-Alive\r\n\r\n`)
    );
  });
}

const dnsAgent = new https.Agent({ keepAlive: true, maxSockets: 8 });
dnsAgent.createConnection = (options, callback) => {
  openTunnel('1.1.1.1', 443).then((socket) => {
    const secure = tls.connect({ socket, servername: 'cloudflare-dns.com', rejectUnauthorized: true });
    let completed = false;
    const deadline = setTimeout(() => { const error = coded('DNS_TLS_TIMEOUT'); secure.destroy(error); finish(error); }, 12000);
    const finish = (error) => {
      if (completed) return;
      completed = true;
      clearTimeout(deadline);
      if (error) { secure.destroy(); callback(error); } else callback(null, secure);
    };
    secure.once('secureConnect', () => finish());
    secure.once('error', finish);
  }, callback);
};

function dnsQuery(host) {
  stats.dnsQueries++;
  return new Promise((resolve, reject) => {
    const request = https.get(
      {
        hostname: 'cloudflare-dns.com',
        port: 443,
        path: '/dns-query?name=' + encodeURIComponent(host) + '&type=A',
        agent: dnsAgent,
        headers: { Accept: 'application/dns-json' }
      },
      (response) => {
        if (response.statusCode !== 200) { response.resume(); reject(coded('DNS_HTTP_ERROR')); return; }
        let text = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => { text += chunk; if (text.length > 1048576) request.destroy(coded('DNS_BODY_TOO_LARGE')); });
        response.on('error', reject);
        response.on('end', () => {
          try {
            const data = JSON.parse(text);
            const answers = (data.Answer || []).filter((a) => a.type === 1 && net.isIPv4(a.data));
            if (data.Status !== 0 || !answers.length) { reject(coded('DNS_NO_IPV4')); return; }
            const ips = [...new Set(answers.map((a) => a.data))];
            const ttl = Math.max(10, Math.min(300, ...answers.map((a) => a.TTL || 30)));
            resolve({ ips, expires: Date.now() + ttl * 1000, index: 0 });
          } catch { reject(coded('DNS_INVALID_JSON')); }
        });
      }
    );
    const totalDeadline = setTimeout(() => request.destroy(coded('DNS_TOTAL_TIMEOUT')), 30000);
    request.once('close', () => clearTimeout(totalDeadline));
    request.setTimeout(15000, () => request.destroy(coded('DNS_TIMEOUT')));
    request.on('error', reject);
  });
}

async function resolveIPv4(host) {
  host = host.replace(/^\[|\]$/g, '');
  if (net.isIPv4(host)) return host;
  if (net.isIP(host)) throw coded('IPV6_NOT_SUPPORTED');
  const key = host.toLowerCase();
  let entry = cache.get(key);
  if (!entry || entry.expires < Date.now()) {
    let promise = pendingDns.get(key);
    if (!promise && pendingDns.size >= 256) throw coded('DNS_QUEUE_FULL');
    if (!promise) { promise = dnsQuery(key); pendingDns.set(key, promise); }
    try { entry = await promise; cache.set(key, entry); } finally { pendingDns.delete(key); }
  }
  if (cache.size > 4096) cache.delete(cache.keys().next().value);
  return entry.ips[entry.index++ % entry.ips.length];
}

setInterval(() => {
  const now = Date.now();
  for (const [key, value] of cache) if (value.expires < now) cache.delete(key);
}, 60000).unref();

function bridge(client, upstream, head) {
  stats.tunnels++;
  stats.active++;
  let ended = false;
  const close = () => { if (ended) return; ended = true; stats.active--; client.destroy(); upstream.destroy(); };
  client.on('error', close);
  upstream.on('error', close);
  client.once('close', close);
  upstream.once('close', close);
  if (head && head.length) upstream.write(head);
  client.pipe(upstream);
  upstream.pipe(client);
  client.resume();
}

const server = http.createServer(async (request, response) => {
  if (request.url === '/health') {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ service: 'StaticChainIPv4Relay', version: 2, upstream: `${UPSTREAM_HOST}:${UPSTREAM_PORT}`, ...stats, cacheEntries: cache.size }));
    return;
  }
  let canceled = false;
  request.once('aborted', () => { canceled = true; });
  response.once('close', () => { canceled = true; });
  request.pause();
  try {
    const url = new URL(request.url);
    if (url.protocol !== 'http:') throw coded('EXPECTED_HTTP_URL');
    const port = Number(url.port || 80);
    const ip = await resolveIPv4(url.hostname);
    const upstream = await openTunnel(ip, port);
    if (canceled || response.destroyed) { upstream.destroy(); return; }
    const headers = { ...request.headers };
    delete headers['proxy-authorization'];
    delete headers['proxy-connection'];
    headers.connection = 'close';
    if (headers['transfer-encoding']) delete headers['content-length'];
    const forward = http.request(
      { hostname: url.hostname, port, method: request.method, path: (url.pathname || '/') + url.search, headers, createConnection: () => upstream },
      (remote) => { response.writeHead(remote.statusCode, remote.headers); remote.pipe(response); remote.on('error', () => response.destroy()); }
    );
    forward.on('error', (error) => { recordError(error); if (!response.headersSent) { response.writeHead(502); response.end('Static proxy unavailable.'); } else response.destroy(); });
    response.once('close', () => { forward.destroy(); upstream.destroy(); });
    request.on('error', () => forward.destroy());
    request.pipe(forward);
    request.resume();
  } catch (error) {
    recordError(error);
    if (!response.headersSent) response.writeHead(502, { 'Content-Type': 'text/plain' });
    response.end('Static proxy unavailable; direct fallback is disabled.');
  }
});

server.on('connect', async (request, client, head) => {
  let canceled = false;
  client.once('close', () => { canceled = true; });
  client.on('error', () => {});
  client.pause();
  try {
    const destination = new URL('http://' + request.url);
    const port = Number(destination.port || 80);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw coded('INVALID_PORT');
    const ip = await resolveIPv4(destination.hostname);
    const upstream = await openTunnel(ip, port);
    if (canceled || client.destroyed) { upstream.destroy(); return; }
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    bridge(client, upstream, head);
  } catch (error) {
    recordError(error);
    client.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
  }
});

server.on('clientError', (_error, socket) => socket.destroy());
server.on('error', (error) => { process.stderr.write(`Static relay listener failed: ${error.code || 'LISTENER_ERROR'}\n`); process.exitCode = 1; });
server.listen(LISTEN_PORT, '127.0.0.1');
process.on('SIGTERM', () => { server.close(() => process.exit(0)); dnsAgent.destroy(); setTimeout(() => process.exit(0), 2000).unref(); });
