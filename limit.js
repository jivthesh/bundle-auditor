export const FREE_PER_DAY = 3;
export const GLOBAL_PER_DAY = 500;

// shortcut: counters live in memory for one process, reset on restart; use Redis or a DB if you run more than one instance.
const hits = new Map();
let total = { day: '', n: 0 };

export function allow(ip, now = Date.now()) {
  const day = new Date(now).toISOString().slice(0, 10);
  if (total.day !== day) { total = { day, n: 0 }; hits.clear(); }
  if (total.n >= GLOBAL_PER_DAY) return { ok: false, reason: 'Daily scan capacity reached. Try an example below or come back tomorrow.' };
  const h = hits.get(ip) || 0;
  if (h >= FREE_PER_DAY) return { ok: false, reason: `Free limit of ${FREE_PER_DAY} scans per day reached. Try an example below or come back tomorrow.` };
  hits.set(ip, h + 1);
  total.n++;
  return { ok: true };
}

// Behind a proxy (Render) the real client is the LAST x-forwarded-for entry: the proxy appends it, earlier entries can be forged.
export function clientIp(req, trustProxy = process.env.TRUST_PROXY) {
  if (trustProxy) {
    const parts = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1];
  }
  return req.socket.remoteAddress;
}
