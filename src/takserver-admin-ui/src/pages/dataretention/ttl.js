// Retention time-to-live helpers. The server stores TTLs as whole seconds
// (Map<String, Integer> in RetentionPolicy); null or negative means keep forever.
// Month and year lengths match the classic page so values it saved read back exactly.

const HOUR = 3600;
const DAY = 24 * HOUR;

export const UNITS = [
  { value: 'hours', label: 'Hours', seconds: HOUR },
  { value: 'days', label: 'Days', seconds: DAY },
  { value: 'weeks', label: 'Weeks', seconds: 7 * DAY },
  { value: 'months', label: 'Months', seconds: 30.42 * DAY },
  { value: 'years', label: 'Years', seconds: 365 * DAY },
];

const unitSeconds = (u) => (UNITS.find((x) => x.value === u) || UNITS[1]).seconds;

// Same 10-year bound as ExpirationWindow.DEFAULT_MAX_WINDOW_SECONDS (takserver-common).
export const MAX_TTL_SECONDS = 10 * 365 * DAY;
export const MIN_TTL_SECONDS = HOUR;

// Data types the classic page offers, in its order, with its descriptions.
export const DATA_TYPES = [
  { key: 'cot', label: 'CoT', description: 'Position reports and other CoT events, except chat' },
  { key: 'geochat', label: 'GeoChat', description: 'Chat messages sent as CoT' },
  { key: 'missionpackages', label: 'Mission packages', description: 'Data packages shared through enterprise sync' },
  { key: 'missions', label: 'Missions', description: 'Mission structure, tracks and files' },
  { key: 'files', label: 'Files', description: 'Enterprise sync files that are not mission data' },
];

export function labelFor(key) {
  return DATA_TYPES.find((t) => t.key === key)?.label || key;
}

/** Server value (seconds or null) to editor row { forever, amount, unit }. */
export function toRow(ttl) {
  if (ttl === null || ttl === undefined || Number(ttl) < 0 || Number.isNaN(Number(ttl))) {
    return { forever: true, amount: '', unit: 'days' };
  }
  const s = Number(ttl);
  for (const u of [...UNITS].reverse()) {
    const n = s / u.seconds;
    if (n >= 1 && Math.abs(n - Math.round(n)) < 1e-9) return { forever: false, amount: String(Math.round(n)), unit: u.value };
  }
  return { forever: false, amount: String(Math.round((s / HOUR) * 100) / 100), unit: 'hours' };
}

/** Editor row to seconds (null for forever). Assumes validateRow passed. */
export function toSeconds(row) {
  if (row.forever) return null;
  return Math.round(Number(row.amount) * unitSeconds(row.unit));
}

/** Error text for a row, or ''. */
export function validateRow(row) {
  if (row.forever) return '';
  if (row.amount === '' || row.amount === null) return 'Enter how long to keep it.';
  const n = Number(row.amount);
  if (!Number.isFinite(n) || n <= 0) return 'Enter a number greater than 0.';
  const s = n * unitSeconds(row.unit);
  if (s < MIN_TTL_SECONDS) return 'Keep data for at least 1 hour.';
  if (s > MAX_TTL_SECONDS) return 'The longest period is 10 years. Choose Keep forever for longer.';
  return '';
}

/** Human text for seconds, e.g. "30 days", "Forever". */
export function describeTtl(ttl) {
  const r = toRow(ttl);
  if (r.forever) return 'forever';
  const n = Number(r.amount);
  const unit = UNITS.find((u) => u.value === r.unit).label.toLowerCase();
  return `${r.amount} ${n === 1 ? unit.replace(/s$/, '') : unit}`;
}

/** True when the new TTL deletes more data than the old one. */
export function isShorter(oldTtl, newTtl) {
  const o = oldTtl === null || oldTtl === undefined || oldTtl < 0 ? Infinity : oldTtl;
  const n = newTtl === null || newTtl === undefined || newTtl < 0 ? Infinity : newTtl;
  return n < o;
}
