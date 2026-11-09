import dns from 'node:dns/promises';
import net from 'node:net';
import zlib from 'node:zlib';

const MAX_BYTES = 5 * 1024 * 1024;
const MAX_SCRIPTS = 25;
const TIMEOUT_MS = 10_000;

const SECRET_PATTERNS = [
  ['AWS access key', /AKIA[0-9A-Z]{16}/g],
  ['Google API key', /AIza[0-9A-Za-z_-]{35}/g],
  ['Stripe live secret key', /sk_live_[0-9a-zA-Z]{24,}/g],
  ['GitHub token', /gh[pousr]_[A-Za-z0-9]{36,}/g],
  ['Slack token', /xox[baprs]-[0-9A-Za-z-]{10,}/g],
  ['Private key block', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
];

export function isPrivateIp(ip) {
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    if (v.startsWith('::ffff:')) return isPrivateIp(v.slice(7));
    return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
  }
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

// shortcut: DNS is resolved once for the check, then fetch resolves again (rebinding gap); pin the IP if this ever faces hostile users at scale.
async function assertPublic(url) {
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only http(s) URLs allowed');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  if (addrs.some((a) => isPrivateIp(a.address))) throw new Error('Private or local addresses are blocked');
}

async function fetchCapped(rawUrl, hops = 0) {
  const url = new URL(rawUrl);
  await assertPublic(url);
  const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
    if (hops >= 3) throw new Error('Too many redirects');
    return fetchCapped(new URL(res.headers.get('location'), url).href, hops + 1);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > MAX_BYTES) throw new Error('Response too large');
  return { url: url.href, status: res.status, body: buf };
}

// shortcut: label heuristic (github ~ githubassets), no public-suffix list; swap in one if odd TLDs cause misses.
export function sameSite(a, b) {
  const root = (h) => h.split('.').slice(-2)[0];
  const x = root(a), y = root(b);
  return x === y || (Math.min(x.length, y.length) >= 4 && (x.startsWith(y) || y.startsWith(x)));
}

export function scanSecrets(text) {
  const hits = [];
  for (const [label, re] of SECRET_PATTERNS) {
    for (const m of text.matchAll(re)) {
      hits.push({ type: label, preview: `${m[0].slice(0, 6)}…(${m[0].length} chars)` });
    }
  }
  return hits;
}

export async function audit(pageUrl) {
  const page = await fetchCapped(pageUrl);
  const html = page.body.toString('utf8');
  const pageHost = new URL(page.url).hostname;

  const srcs = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map((m) => new URL(m[1], page.url).href)
    .slice(0, MAX_SCRIPTS);

  const scripts = [];
  for (const src of srcs) {
    try {
      const r = await fetchCapped(src);
      const text = r.body.toString('utf8');
      scripts.push({
        url: src,
        thirdParty: !sameSite(new URL(src).hostname, pageHost),
        bytes: r.body.length,
        gzipBytes: zlib.gzipSync(r.body).length,
        sourceMapExposed: /\/\/# sourceMappingURL=/.test(text),
        secrets: scanSecrets(text),
      });
    } catch (e) {
      scripts.push({ url: src, error: e.message });
    }
  }

  const ok = scripts.filter((s) => !s.error);
  return {
    page: page.url,
    status: page.status,
    scriptCount: scripts.length,
    totalBytes: ok.reduce((n, s) => n + s.bytes, 0),
    totalGzipBytes: ok.reduce((n, s) => n + s.gzipBytes, 0),
    thirdPartyHosts: [...new Set(ok.filter((s) => s.thirdParty).map((s) => new URL(s.url).hostname))],
    secretFindings: ok.flatMap((s) => s.secrets.map((x) => ({ ...x, script: s.url }))),
    sourceMapsExposed: ok.filter((s) => s.sourceMapExposed).map((s) => s.url),
    scripts,
  };
}
