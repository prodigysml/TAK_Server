// Pure helpers for the overview page: parse TAK's response shapes, format values.

export const DAY_MS = 24 * 60 * 60 * 1000;
export const CERT_WINDOW_DAYS = 30;

// Same freshness thresholds as the classic clients page health icon
// (Marti/clients/js/controllers.js getHealthIcon): <10s current, <3min stale.
export const FRESH_MS = 10 * 1000;
export const STALE_MS = 3 * 60 * 1000;

// TakCert dates use tak.server.Constants.COT_DATE_FORMAT, "yyyy-MM-dd'T'HH:mm:ss.S'Z'" (UTC).
// The fraction can be 1-3 digits, which Date.parse doesn't reliably accept, so parse by hand.
export function parseTakDate(v) {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v === 'number') return new Date(v);
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z?$/.exec(String(v));
  if (!m) {
    const t = Date.parse(String(v));
    return Number.isNaN(t) ? null : new Date(t);
  }
  const ms = m[7] ? Number(m[7].padEnd(3, '0')) : 0;
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms));
}

// /Marti/api/security/isSecure returns data "true", or the Java toString of the
// non-secure port collection, e.g. "[8087, 8080]".
export function parseSecure(data) {
  if (data === true || data === 'true') return { secure: true, ports: [] };
  const ports = String(data ?? '').match(/\d+/g) || [];
  return { secure: false, ports: ports.map(Number) };
}

export function commonName(dn) {
  const m = /(?:^|,)\s*CN=([^,]+)/i.exec(String(dn || ''));
  return (m ? m[1] : String(dn || '')).trim() || 'Unnamed certificate';
}

export function plural(n, one, many = `${one}s`) {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

export function countBy(list, keyFn) {
  const map = new Map();
  list.forEach((x) => {
    const k = keyFn(x);
    map.set(k, (map.get(k) || 0) + 1);
  });
  return [...map.entries()].map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count || String(a.label).localeCompare(String(b.label)));
}

export function protocolLabel(p) {
  const v = String(p || '').trim();
  if (!v) return 'Unknown';
  if (v === 'WebSockets') return v;
  return v.toUpperCase();
}

export function formatDate(d) {
  if (!d) return '';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function formatTime(d) {
  if (!d) return '';
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function daysUntil(d, now = Date.now()) {
  return Math.ceil((d.getTime() - now) / DAY_MS);
}

export function expiresPhrase(days) {
  if (days <= 0) return 'Expires today';
  if (days === 1) return 'Expires tomorrow';
  return `Expires in ${days} days`;
}

export function compactNumber(n) {
  const v = Number(n) || 0;
  return v.toLocaleString(undefined, v >= 100000 ? { notation: 'compact', maximumFractionDigits: 1 } : undefined);
}

export function formatBytes(n) {
  let v = Number(n) || 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

// Protocols that carry traffic in the clear (SubmissionApi.PROTOCOLS minus the TLS ones).
const PLAINTEXT = new Set(['tcp', 'udp', 'stcp', 'mcast', 'cotmcast']);
export function isPlaintextProtocol(p) {
  return PLAINTEXT.has(String(p || '').toLowerCase());
}

// Expiring-soon certificates from /Marti/api/certadmin/cert/active (List<TakCert>).
export function expiringCerts(certs, now = Date.now()) {
  const limit = now + CERT_WINDOW_DAYS * DAY_MS;
  return (Array.isArray(certs) ? certs : [])
    .map((c) => ({ cert: c, expires: parseTakDate(c?.expirationDate) }))
    .filter((x) => x.expires && x.expires.getTime() <= limit)
    .map((x) => ({ ...x, days: daysUntil(x.expires, now), name: commonName(x.cert.subjectDn) }))
    .sort((a, b) => a.expires - b.expires);
}

// Split /Marti/api/inputs (SortedSet<InputMetric>) into plain inputs and data feeds.
// Classic inputs page treats anything with input.type set as a data feed.
export function splitInputs(list) {
  const all = Array.isArray(list) ? list : [];
  return {
    inputs: all.filter((m) => m?.input && (m.input.type === null || m.input.type === undefined || m.input.type === '')),
    feeds: all.filter((m) => m?.input && m.input.type),
  };
}
