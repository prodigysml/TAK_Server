// Helpers for the client certificates page. Shapes follow TakCert.java
// (takserver-war/src/main/java/com/bbn/tak/tls/TakCert.java).

export const BASE = '/Marti/api/certadmin/cert';

// Server-side caps on id lists (CertManagerAdminApi.MAX_BULK_IDS / MAX_REVOKE_IDS).
export const LIMITS = { download: 100, delete: 100, revoke: 50 };

export const EXPIRING_DAYS = 30;
const DAY = 24 * 60 * 60 * 1000;

// Dates arrive as "yyyy-MM-dd'T'HH:mm:ss.S'Z'" in UTC, where .S is the raw
// millisecond count (".5" means 5 ms), so parse it by hand instead of Date.parse.
export function parseDate(v) {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v === 'number') return new Date(v);
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z?$/.exec(String(v));
  if (m) {
    const ms = m[7] ? Math.min(999, parseInt(m[7], 10)) : 0;
    return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms));
  }
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

// The database column is a DATE, so the day is what matters. Show it in UTC.
export function formatAbsolute(d) {
  if (!d) return '';
  return d.toISOString().slice(0, 10);
}

export function formatFull(d) {
  if (!d) return '';
  return `${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

const rtf = typeof Intl !== 'undefined' && Intl.RelativeTimeFormat
  ? new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
  : null;

export function formatRelative(d, now = Date.now()) {
  if (!d || !rtf) return '';
  const diff = d.getTime() - now;
  const abs = Math.abs(diff);
  if (abs < DAY) return rtf.format(Math.round(diff / (60 * 60 * 1000)), 'hour');
  if (abs < 60 * DAY) return rtf.format(Math.round(diff / DAY), 'day');
  if (abs < 730 * DAY) return rtf.format(Math.round(diff / (30 * DAY)), 'month');
  return rtf.format(Math.round(diff / (365 * DAY)), 'year');
}

// Pull CN=... out of a DN for display. Falls back to the whole DN.
export function commonName(dn) {
  if (!dn) return '';
  for (const part of String(dn).split(',')) {
    const t = part.trim();
    if (/^cn=/i.test(t)) return t.slice(3);
  }
  return String(dn);
}

// The server reports only `hasToken`; the enrollment token itself (a live bearer
// credential) is never serialized. Older servers did send `token`, so drop it if
// present so it is never rendered or kept in state.
export function sanitize(cert) {
  if (!cert || typeof cert !== 'object') return cert;
  const { token, ...rest } = cert;
  const legacy = typeof token === 'string' && token.length > 0;
  return { ...rest, hasToken: rest.hasToken === true || legacy };
}

export const STATUS = {
  active: { label: 'Active', color: 'success' },
  expiring: { label: 'Expires soon', color: 'warning' },
  replaced: { label: 'Replaced', color: 'default' },
  expired: { label: 'Expired', color: 'error' },
  revoked: { label: 'Revoked', color: 'error' },
};

// Revoked beats expired beats replaced. "Expires soon" is an active cert that
// expires within EXPIRING_DAYS.
export function deriveStatus(row, replacedIds, now = Date.now()) {
  const revoked = parseDate(row.revocationDate);
  if (revoked && revoked.getTime() <= now) return 'revoked';
  const exp = parseDate(row.expirationDate);
  if (exp && exp.getTime() <= now) return 'expired';
  if (replacedIds.has(row.id)) return 'replaced';
  if (exp && exp.getTime() - now <= EXPIRING_DAYS * DAY) return 'expiring';
  return 'active';
}

export function plural(n, word) {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}
