import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer, request } from 'node:http';
import { createServer as createTcpServer, connect } from 'node:net';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

// Synthetic traffic only. Never reads subscription data or changes proxy/TUN.
const core = process.argv[2];
if (!core) throw new Error('Usage: node tools/core-loopback-smoke.mjs <nekobox_core.exe>');
const directory = await mkdtemp(join(tmpdir(), 'mdmbox-loopback-'));
let child;
let childExit;
let spawnError;
let logs = '';
let originRequests = 0;
const origin = createServer((req, res) => {
  originRequests++;
  if (req.method !== 'GET' || req.url !== '/mdmbox-smoke') {
    res.writeHead(400).end();
    return;
  }
  res.writeHead(200, { 'content-type': 'text/plain', connection: 'close' });
  res.end('MDMBOX_LOOPBACK_PASS');
});

try {
  origin.listen(0, '127.0.0.1');
  await once(origin, 'listening');
  const originPort = origin.address().port;
  // Reserve an ephemeral port, then release it immediately before core start.
  // A collision remains possible: readiness/request assertions fail safely.
  const reservation = createTcpServer();
  reservation.listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const proxyPort = reservation.address().port;
  await new Promise((done, reject) => reservation.close(err => err ? reject(err) : done()));
  const config = join(directory, 'config.json');
  await writeFile(config, JSON.stringify({
    log: { level: 'error' },
    inbounds: [{ type: 'http', tag: 'smoke-in', listen: '127.0.0.1', listen_port: proxyPort }],
    outbounds: [{ type: 'direct', tag: 'direct' }],
  }));
  child = spawn(resolve(core), ['run', '-c', config, '--disable-color'], {
    cwd: directory, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  });
  childExit = new Promise(done => {
    child.once('error', error => { spawnError = error; done(); });
    child.once('exit', done);
  });
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', data => { logs = (logs + data.toString()).slice(-8192); });
  }
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (spawnError) throw spawnError;
    if (child.exitCode !== null) throw new Error('Core exited before readiness');
    ready = await new Promise(done => {
      const socket = connect({ host: '127.0.0.1', port: proxyPort });
      const finish = value => { socket.destroy(); done(value); };
      socket.setTimeout(150, () => finish(false));
      socket.once('error', () => finish(false));
      socket.once('connect', () => finish(true));
    });
    if (ready) break;
    await delay(100);
  }
  assert.ok(ready, 'Core did not become ready');
  const result = await new Promise((done, reject) => {
    const req = request({
      host: '127.0.0.1', port: proxyPort, method: 'GET',
      path: `http://127.0.0.1:${originPort}/mdmbox-smoke`,
      headers: { host: `127.0.0.1:${originPort}`, connection: 'close' },
      agent: false,
    }, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('error', reject);
      res.on('data', chunk => {
        body += chunk;
        if (body.length > 1024) res.destroy(new Error('Unexpected response size'));
      });
      res.on('end', () => done({ status: res.statusCode, body }));
    });
    req.setTimeout(5000, () => req.destroy(new Error('Proxy request timeout')));
    req.on('error', reject);
    req.end();
  });
  assert.equal(result.status, 200);
  assert.equal(result.body, 'MDMBOX_LOOPBACK_PASS');
  assert.equal(originRequests, 1);
  assert.equal(child.exitCode, null, 'Core exited unexpectedly');
  console.log(JSON.stringify({ status: 'PASS', scope: 'HTTP proxy to loopback origin', originRequests,
    externalNetwork: 'NOT_TESTED', tun: 'NOT_TESTED', rpc: 'NOT_TESTED' }));
} catch (error) {
  console.error('Loopback smoke FAILED:', error.message);
  // Only bounded logs from this synthetic, freshly generated config.
  if (logs) console.error(logs);
  process.exitCode = 1;
} finally {
  if (child && !spawnError && child.exitCode === null) child.kill();
  if (childExit) await childExit;
  origin.closeAllConnections();
  await new Promise(done => origin.close(done));
  await rm(directory, { recursive: true, force: true });
}
