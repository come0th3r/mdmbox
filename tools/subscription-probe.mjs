import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const MAX_BYTES = 4 * 1024 * 1024;
const MAX_INTERVAL_HOURS = 24 * 30;

export function buildRequestUrl(rawUrl, format = 'uri') {
  const url = new URL(rawUrl);
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw new Error('An HTTPS subscription URL without embedded credentials is required.');
  }
  if (!['uri', 'clash', 'singbox'].includes(format)) throw new Error('Unsupported format.');
  url.hash = '';
  url.searchParams.set('format', format);
  return url;
}

export function parseMetadata(headers) {
  const fields = {};
  for (const part of (headers.get('subscription-userinfo') ?? '').split(';')) {
    const match = /^\s*(upload|download|total|expire)\s*=\s*(\d+)\s*$/.exec(part);
    // Decimal strings preserve counters beyond JavaScript's safe-integer range.
    if (match) fields[match[1]] = BigInt(match[2]).toString();
  }
  const interval = headers.get('profile-update-interval');
  const hours = interval && /^\d+$/.test(interval.trim()) ? Number(interval) : null;
  return {
    userInfoFields: Object.keys(fields).sort(),
    hasTrafficMetadata: ['upload', 'download', 'total'].every(key => key in fields),
    hasExpiryMetadata: 'expire' in fields,
    updateIntervalHours: hours > 0 && hours <= MAX_INTERVAL_HOURS ? hours : null,
    hasTitle: Boolean(headers.get('profile-title')),
    hasSupportUrl: Boolean(headers.get('support-url')),
    hasPageUrl: Boolean(headers.get('profile-web-page-url')),
    deviceNotice: ['x-hwid-not-supported', 'x-hwid-max-devices-reached', 'x-hwid-limit']
      .some(key => headers.get(key)?.toLowerCase() === 'true'),
  };
}

function counts(values) {
  const result = new Map();
  for (const value of values) {
    const safe = typeof value === 'string' && /^[a-z][a-z0-9+.-]{0,31}$/i.test(value)
      ? value.toLowerCase() : 'unknown';
    result.set(safe, (result.get(safe) ?? 0) + 1);
  }
  return Object.fromEntries(result);
}

export function summarizeBody(body) {
  const text = body.replace(/^\uFEFF/, '').trim();
  if (!text) return { kind: 'empty', usableCandidate: false };
  if (/^<(?:!doctype|html|head|body)\b/i.test(text)) {
    return { kind: 'html', usableCandidate: false };
  }
  if (/^[{[]/.test(text)) {
    try {
      const data = JSON.parse(text);
      if (!data || Array.isArray(data) || !Array.isArray(data.outbounds)) {
        return { kind: 'json-other', usableCandidate: false };
      }
      return {
        kind: 'singbox-json', usableCandidate: data.outbounds.length > 0,
        outboundCount: data.outbounds.length,
        outboundTypes: counts(data.outbounds.map(item => item?.type)),
        routeRuleCount: Array.isArray(data.route?.rules) ? data.route.rules.length : 0,
        ruleSetCount: Array.isArray(data.route?.rule_set) ? data.route.rule_set.length : 0,
        hasDns: Boolean(data.dns && typeof data.dns === 'object'),
      };
    } catch { return { kind: 'invalid-json', usableCandidate: false }; }
  }
  // Structural hints only: this is deliberately NOT a YAML parser or a core validator.
  if (/^proxies\s*:/m.test(text)) {
    const keys = ['proxies', 'proxy-groups', 'rules', 'rule-providers', 'dns'];
    return { kind: 'clash-yaml-candidate', usableCandidate: false, requiresCoreValidation: true,
      topLevelSections: keys.filter(key => new RegExp(`^${key}\\s*:`, 'm').test(text)) };
  }
  let links = text;
  let encoding = 'plain';
  if (/^[A-Za-z0-9+/_=\s-]+$/.test(text)) {
    const compact = text.replace(/\s/g, '');
    if (compact.length % 4 !== 1) {
      links = Buffer.from(compact, 'base64').toString('utf8').trim();
      encoding = 'base64';
    }
  }
  const lines = links.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const schemes = lines.map(line => /^([a-z][a-z0-9+.-]*):\/\//i.exec(line)?.[1]);
  if (schemes.length && schemes.every(Boolean)) {
    return { kind: 'uri-list', encoding, usableCandidate: true,
      linkCount: schemes.length, protocolCounts: counts(schemes) };
  }
  return { kind: 'unrecognized', usableCandidate: false };
}

async function readLimited(response, limit) {
  const declared = response.headers.get('content-length');
  if (declared && /^\d+$/.test(declared) && BigInt(declared) > BigInt(limit)) {
    await response.body?.cancel();
    throw new Error('Response exceeds the size limit.');
  }
  const reader = response.body?.getReader();
  if (!reader) return { text: '', bytes: 0 };
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > limit) {
        await reader.cancel();
        throw new Error('Response exceeds the size limit.');
      }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  return { text: Buffer.concat(chunks).toString('utf8'), bytes };
}

export async function probeSubscription({ url, format = 'uri', userAgent = 'MDMBOX-contract-probe/0.1',
  method = 'HEAD', hwid, timeoutMs = 20000, maxBytes = MAX_BYTES, fetchImpl = fetch }) {
  if (!['HEAD', 'GET'].includes(method)) throw new Error('Only HEAD and GET are supported.');
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 120000) throw new Error('Invalid timeout.');
  if (!Number.isInteger(maxBytes) || maxBytes <= 0 || maxBytes > MAX_BYTES) throw new Error('Invalid size limit.');
  const target = buildRequestUrl(url, format);
  const requestHeaders = { 'User-Agent': userAgent,
    Accept: format === 'clash' ? 'text/yaml' : format === 'singbox' ? 'application/json' : 'text/plain' };
  if (hwid) {
    // Prevent raw identifiers supplied by a caller from being reflected into reports.
    requestHeaders['X-Hwid'] = hwid;
    requestHeaders['X-Device-Os'] = 'Windows';
  }
  const response = await fetchImpl(target, {
    method, redirect: 'manual', headers: requestHeaders, signal: AbortSignal.timeout(timeoutMs),
  });
  const report = {
    method, requestedFormat: format, httpStatus: response.status,
    metadata: parseMetadata(response.headers),
    redirectBlocked: response.status >= 300 && response.status < 400,
    validation: 'NOT_RUN', connectionTest: 'NOT_RUN',
  };
  if (method === 'GET' && response.ok) {
    const body = await readLimited(response, maxBytes);
    report.bodyBytes = body.bytes;
    report.body = summarizeBody(body.text);
  } else {
    await response.body?.cancel();
  }
  // No URL, endpoint, account values, title, link, credential or raw body in output.
  return report;
}

async function main() {
  const args = new Set(process.argv.slice(2));
  if ([...args].some(arg => !['--get', '--help'].includes(arg))) throw new Error('Unknown option.');
  if (args.has('--help')) {
    console.log('Set MDMBOX_TEST_SUBSCRIPTION_URL; optional MDMBOX_PROBE_FORMAT and MDMBOX_PROBE_USER_AGENT.\n'
      + 'Default: HEAD. Use --get for a bounded, in-memory body summary. No raw profile is saved.\n'
      + 'GET may register a device; set a stable MDMBOX_TEST_HWID when device binding requires it.\n'
      + 'Optional MDMBOX_PROBE_HWID_RANDOM=1 generates an ephemeral test ID (not recommended for repeated GET).');
    return;
  }
  const url = process.env.MDMBOX_TEST_SUBSCRIPTION_URL;
  if (!url) throw new Error('Set MDMBOX_TEST_SUBSCRIPTION_URL.');
  const report = await probeSubscription({ url, method: args.has('--get') ? 'GET' : 'HEAD',
    format: process.env.MDMBOX_PROBE_FORMAT || 'uri',
    userAgent: process.env.MDMBOX_PROBE_USER_AGENT || 'MDMBOX-contract-probe/0.1',
    hwid: process.env.MDMBOX_TEST_HWID || (process.env.MDMBOX_PROBE_HWID_RANDOM === '1' ? randomUUID() : undefined) });
  console.log(JSON.stringify(report, null, 2));
  if (report.httpStatus !== 200 || report.metadata.deviceNotice) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    // Never print error.message/cause/stack: network errors can contain the secret URL.
    console.error(JSON.stringify({ status: 'BLOCKED', errorType: error?.name || 'Error',
      hint: 'Check private input, TLS, connectivity and response-size limits. Raw errors are suppressed.' }));
    process.exitCode = 1;
  });
}
