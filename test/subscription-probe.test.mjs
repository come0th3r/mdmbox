import assert from 'node:assert/strict';
import test from 'node:test';
import { buildRequestUrl, parseMetadata, probeSubscription, summarizeBody } from '../tools/subscription-probe.mjs';

const url = 'https://panel.example/custom/private-token?extra=keep&format=uri&format=base64#fragment';

test('format replacement preserves custom paths and unrelated query without duplicate format', () => {
  const result = buildRequestUrl(url, 'clash');
  assert.equal(result.pathname, '/custom/private-token');
  assert.equal(result.searchParams.get('extra'), 'keep');
  assert.deepEqual(result.searchParams.getAll('format'), ['clash']);
  assert.equal(result.hash, '');
});

test('rejects insecure URLs, URL credentials and unknown formats', () => {
  for (const value of ['http://panel.example/token', 'https://user:pass@panel.example/token', 'file:///secret']) {
    assert.throws(() => buildRequestUrl(value));
  }
  assert.throws(() => buildRequestUrl(url, 'html'));
});

test('metadata recognizes large decimal traffic values without reporting account values', () => {
  const result = parseMetadata(new Headers({
    'Subscription-Userinfo': 'upload=9007199254740993; download=4; total=0; expire=0',
    'Profile-Title': 'base64:cHJpdmF0ZQ==', 'Profile-Update-Interval': '1',
    'Support-Url': 'https://support.example', 'X-Hwid-Limit': 'true',
  }));
  assert.equal(result.hasTrafficMetadata, true);
  assert.equal(result.hasExpiryMetadata, true);
  assert.equal(result.updateIntervalHours, 1);
  assert.equal(result.deviceNotice, true);
  assert.equal(JSON.stringify(result).includes('9007199254740993'), false);
  assert.equal(JSON.stringify(result).includes('cHJpdmF0ZQ'), false);
});

test('malformed metadata and unbounded intervals are not accepted', () => {
  for (const interval of ['0', '-1', 'NaN', '1.5', '99999999999999999999']) {
    const result = parseMetadata(new Headers({ 'Profile-Update-Interval': interval,
      'Subscription-Userinfo': 'upload=-1; download=nope; total=2' }));
    assert.equal(result.updateIntervalHours, null);
    assert.equal(result.hasTrafficMetadata, false);
  }
});

test('plain and Base64 links only expose protocol counts', () => {
  const links = 'vless://private-uuid@hidden.example:443#private-name\ntrojan://password@hidden.example:443';
  for (const text of [links, Buffer.from(links).toString('base64')]) {
    const result = summarizeBody(text);
    assert.equal(result.kind, 'uri-list');
    assert.deepEqual(result.protocolCounts, { vless: 1, trojan: 1 });
    assert.equal(result.linkCount, 2);
    assert.doesNotMatch(JSON.stringify(result), /private|hidden|password/);
  }
});

test('JSON retains route/DNS structure in summary, not secrets or unsafe types', () => {
  const result = summarizeBody(JSON.stringify({ outbounds: [{ type: 'vless', uuid: 'private-uuid' },
    { type: 'https://private.example' }], dns: {}, route: { rules: [{}], rule_set: [{ url: 'https://private.example' }] } }));
  assert.equal(result.kind, 'singbox-json');
  assert.deepEqual(result.outboundTypes, { vless: 1, unknown: 1 });
  assert.equal(result.routeRuleCount, 1);
  assert.equal(result.ruleSetCount, 1);
  assert.equal(result.hasDns, true);
  assert.doesNotMatch(JSON.stringify(result), /private/);
});

test('YAML hints do not claim parsing, core validation or usable profiles', () => {
  const result = summarizeBody('proxies:\n  - name: secret\nproxy-groups: []\nrules: []\nrule-providers: {}\ndns: {}');
  assert.equal(result.kind, 'clash-yaml-candidate');
  assert.equal(result.usableCandidate, false);
  assert.equal(result.requiresCoreValidation, true);
  assert.equal(result.topLevelSections.length, 5);
});

test('protocol counters handle inherited property names without prototype collisions', () => {
  const result = summarizeBody('constructor://synthetic\nconstructor://synthetic');
  assert.equal(result.protocolCounts.constructor, 2);
});

test('HTTP failures do not parse or expose the error body', async () => {
  for (const status of [401, 403, 404, 429, 500, 503]) {
    const result = await probeSubscription({ url, method: 'GET',
      fetchImpl: async () => new Response('private error body', { status }) });
    assert.equal(result.httpStatus, status);
    assert.equal(result.body, undefined);
    assert.doesNotMatch(JSON.stringify(result), /private/);
  }
});

test('empty, HTML, truncated JSON and junk are not usable candidates', () => {
  for (const body of ['', '<!doctype html><html>private</html>', '{"outbounds":', 'garbage']) {
    assert.equal(summarizeBody(body).usableCandidate, false);
  }
});

test('probe blocks redirects and never includes location, URL or headers in report', async () => {
  let requests = 0;
  const result = await probeSubscription({ url, fetchImpl: async (target, options) => {
    requests++;
    assert.equal(options.redirect, 'manual');
    assert.equal(options.method, 'HEAD');
    return new Response(null, { status: 302, headers: { location: 'https://other.example/private-token' } });
  } });
  assert.equal(requests, 1);
  assert.equal(result.redirectBlocked, true);
  assert.equal(result.validation, 'NOT_RUN');
  assert.equal(result.connectionTest, 'NOT_RUN');
  assert.doesNotMatch(JSON.stringify(result), /private|panel\.example|other\.example/);
});

test('GET stays in memory, sends supplied HWID and summarizes instead of disclosing', async () => {
  const result = await probeSubscription({ url, method: 'GET', hwid: 'private-stable-id',
    fetchImpl: async (target, options) => {
      assert.equal(options.headers['X-Hwid'], 'private-stable-id');
      return new Response('vless://private@secret.example:443', { status: 200 });
    } });
  assert.equal(result.body.linkCount, 1);
  assert.doesNotMatch(JSON.stringify(result), /private|secret\.example/);
});

test('response-size limits apply to both declared length and streamed bytes', async () => {
  for (const headers of [{}, { 'content-length': '1000' }]) {
    await assert.rejects(probeSubscription({ url, method: 'GET', maxBytes: 3,
      fetchImpl: async () => new Response('too long', { headers }) }), /size limit/);
  }
});

test('rejects invalid settings before making requests', async () => {
  const fetchImpl = () => { throw new Error('Unexpected network call'); };
  for (const options of [{ method: 'POST' }, { timeoutMs: 0 }, { maxBytes: -1 }, { timeoutMs: 120001 }]) {
    await assert.rejects(probeSubscription({ url, fetchImpl, ...options }));
  }
});
