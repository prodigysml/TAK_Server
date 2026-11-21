// Shared helpers for the Missions page. Everything here renders server data as text.

export const MISSIONS = '/Marti/api/missions';

// Paths built from fixed strings plus encoded segments only.
export const missionPath = (name, suffix = '') => `${MISSIONS}/${encodeURIComponent(String(name))}${suffix}`;
export const fileHref = (hash) => `/Marti/api/files/${encodeURIComponent(String(hash))}`;

export const ROLES = [
  { value: 'MISSION_SUBSCRIBER', label: 'Subscriber' },
  { value: 'MISSION_READONLY_SUBSCRIBER', label: 'Read-only subscriber' },
  { value: 'MISSION_OWNER', label: 'Owner' },
];

export function roleLabel(type) {
  return ROLES.find((r) => r.value === type)?.label || (type ? String(type) : 'Not set');
}

// TAK serialises dates as yyyy-MM-dd'T'HH:mm:ss.SSS'Z' (UTC).
export function parseDate(v) {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

export function formatDate(v) {
  const d = v instanceof Date ? v : parseDate(v);
  return d ? dtf.format(d) : '';
}

// Mission expiration is Unix seconds; null or -1 means it never expires.
export function expirationDate(seconds) {
  if (seconds === null || seconds === undefined || Number(seconds) < 0) return null;
  const d = new Date(Number(seconds) * 1000);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatBytes(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0) return '';
  if (v < 1024) return `${v} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let x = v / 1024;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) { x /= 1024; i += 1; }
  return `${x < 10 ? x.toFixed(1) : Math.round(x)} ${units[i]}`;
}

export const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export const asArray = (v) => (Array.isArray(v) ? v : []);
export const text = (v) => (v === null || v === undefined ? '' : String(v));

// Mirrors the server's MartiSafeString rule (validation.properties), minus "/" and "\",
// which would break the mission's URL path.
const SAFE = /^[\p{L}\p{N}\w\s.()!=@#$&^*\-+[\]{}:,|]*$/u;
// The server rule itself, for query-parameter fields such as description.
const SAFE_PARAM = /^[\p{L}\p{N}\w\s.()!=@#$&^*\-+[\]{}:,|/\\]*$/u;

export function validateMissionName(raw) {
  const name = raw.trim();
  if (!name) return 'Enter a mission name.';
  if (name.length > 1024) return 'Use 1024 characters or fewer.';
  if (!SAFE.test(name)) return 'Use letters, numbers, spaces and . ( ) ! = @ # $ & ^ * _ - + [ ] { } : , | only.';
  return '';
}

export function validateSafeText(raw, label) {
  if (!raw) return '';
  if (raw.length > 1024) return `${label} must be 1024 characters or fewer.`;
  if (!SAFE_PARAM.test(raw)) return `${label} can't contain < > " ' ; % ? ~ or backticks.`;
  return '';
}
