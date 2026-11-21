// Spring 6-field cron helpers: "second minute hour day-of-month month day-of-week".
// TAK uses "-" to mean "never run". No dependency: covers the presets this page
// generates and simple numeric expressions; anything else falls back to the raw text.

export const DISABLED = '-';
export const MAX_CRON_LENGTH = 256; // RetentionApi.setRetentionServiceSchedule rejects longer bodies

export const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const DAY_NAMES = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
const MACROS = {
  '@yearly': 'Once a year, at midnight on 1 January',
  '@annually': 'Once a year, at midnight on 1 January',
  '@monthly': 'Once a month, at midnight on the 1st',
  '@weekly': 'Once a week, at midnight on Sunday',
  '@daily': 'Every day at 00:00',
  '@midnight': 'Every day at 00:00',
  '@hourly': 'Every hour, on the hour',
};

const isInt = (s) => /^\d{1,2}$/.test(s);
const any = (s) => s === '*' || s === '?';
const pad = (n) => String(n).padStart(2, '0');

function dayOfWeek(s) {
  if (isInt(s)) {
    const n = Number(s);
    return n >= 0 && n <= 7 ? n % 7 : null;
  }
  const i = DAY_NAMES.indexOf(String(s).toUpperCase());
  return i >= 0 ? i : null;
}

/** Split into 6 fields, or null if the shape is wrong. */
function fields(expr) {
  const parts = String(expr || '').trim().split(/\s+/);
  return parts.length === 6 ? parts : null;
}

/**
 * Light syntax check, mirroring what Spring's CronExpression accepts closely enough
 * to catch typos before the server silently ignores an invalid expression.
 * Returns an error message, or '' when it looks valid.
 */
export function validateCron(expr) {
  const v = String(expr ?? '').trim();
  if (!v) return 'Enter a cron expression, or choose Never.';
  if (v.length > MAX_CRON_LENGTH) return `Keep it under ${MAX_CRON_LENGTH} characters.`;
  if (v === DISABLED) return '';
  if (v.startsWith('@')) return MACROS[v.toLowerCase()] ? '' : 'Unknown shortcut. Use @hourly, @daily, @weekly, @monthly or @yearly.';
  const f = fields(v);
  if (!f) return 'Use 6 fields: second minute hour day-of-month month day-of-week (for example 0 0 2 * * *).';
  if (f.some((x) => !/^[A-Za-z0-9*?,/#\-LW]+$/.test(x))) return 'Only digits, names and the characters * ? , / - # L W are allowed.';
  const ranges = [[0, 59, 'Second'], [0, 59, 'Minute'], [0, 23, 'Hour'], [1, 31, 'Day of month'], [1, 12, 'Month'], [0, 7, 'Day of week']];
  for (let i = 0; i < 6; i += 1) {
    if (isInt(f[i])) {
      const n = Number(f[i]);
      const [lo, hi, name] = ranges[i];
      if (n < lo || n > hi) return `${name} must be between ${lo} and ${hi}.`;
    }
  }
  return '';
}

/**
 * Recognise one of the editor's presets.
 * Returns { kind, minute, hour, dow, dom } with kind in never|hourly|daily|weekly|monthly|custom.
 */
export function parsePreset(expr) {
  const v = String(expr ?? '').trim();
  const base = { minute: 0, hour: 2, dow: 0, dom: 1 };
  if (v === DISABLED || v === '') return { ...base, kind: 'never' };
  const f = fields(v);
  if (!f || f[0] !== '0' || !isInt(f[1]) || f[4] !== '*') return { ...base, kind: 'custom' };
  const minute = Number(f[1]);
  if (minute > 59) return { ...base, kind: 'custom' };
  const [, , h, dom, , dow] = f;
  if (any(h) && any(dom) && any(dow)) return { ...base, minute, kind: 'hourly' };
  if (!isInt(h) || Number(h) > 23) return { ...base, kind: 'custom' };
  const hour = Number(h);
  if (any(dom) && any(dow)) return { ...base, minute, hour, kind: 'daily' };
  if (any(dom) && dayOfWeek(dow) !== null) return { ...base, minute, hour, dow: dayOfWeek(dow), kind: 'weekly' };
  if (isInt(dom) && Number(dom) >= 1 && Number(dom) <= 31 && any(dow)) return { ...base, minute, hour, dom: Number(dom), kind: 'monthly' };
  return { ...base, kind: 'custom' };
}

/** Build the cron expression for a preset. */
export function buildPreset({ kind, minute = 0, hour = 0, dow = 0, dom = 1 }) {
  switch (kind) {
    case 'never': return DISABLED;
    case 'hourly': return `0 ${minute} * * * *`;
    case 'daily': return `0 ${minute} ${hour} * * *`;
    case 'weekly': return `0 ${minute} ${hour} * * ${dow}`;
    case 'monthly': return `0 ${minute} ${hour} ${dom} * *`;
    default: return null;
  }
}

function step(s) {
  const m = /^(?:\*|0)\/(\d{1,2})$/.exec(s);
  return m ? Number(m[1]) : null;
}

function ordinal(n) {
  const s = ['th', 'st', 'nd', 'rd'];
  const v = n % 100;
  return n + (s[(v - 20) % 10] || s[v] || s[0]);
}

function list(items) {
  if (items.length <= 1) return items.join('');
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

/**
 * Plain-English description, or null when the expression is outside what this
 * helper understands (the caller then shows the raw expression).
 */
export function describeCron(expr) {
  const v = String(expr ?? '').trim();
  if (v === DISABLED) return 'Never runs. The schedule is turned off.';
  if (MACROS[v.toLowerCase()]) return MACROS[v.toLowerCase()];
  const f = fields(v);
  if (!f) return null;
  const [sec, min, hour, dom, mon, dow] = f;
  if (!any(mon)) return null;
  if (!isInt(sec)) return null;
  const secPart = Number(sec) ? `:${pad(sec)}` : '';

  // Sub-hourly and hourly patterns.
  if (any(hour) && any(dom) && any(dow)) {
    if (min === '*') return Number(sec) ? `Every minute at ${Number(sec)} seconds past` : 'Every minute';
    const ms = step(min);
    if (ms) return `Every ${ms} minutes`;
    if (isInt(min)) return Number(min) === 0 ? 'Every hour, on the hour' : `Every hour at ${Number(min)} minutes past the hour`;
    return null;
  }
  const hs = step(hour);
  if (hs && isInt(min) && any(dom) && any(dow)) {
    return Number(min) === 0 ? `Every ${hs} hours, on the hour` : `Every ${hs} hours, at ${Number(min)} minutes past the hour`;
  }

  // Fixed time of day, possibly several hours ("2,14").
  if (!isInt(min)) return null;
  const hours = hour.split(',');
  if (!hours.every(isInt)) return null;
  const at = `at ${list(hours.map((h) => `${pad(h)}:${pad(min)}${secPart}`))}`;

  if (any(dom) && any(dow)) return `Every day ${at}`;
  if (any(dom)) {
    const days = dow.split(',').map(dayOfWeek);
    if (days.some((d) => d === null)) {
      const r = /^([A-Za-z]{3}|\d)-([A-Za-z]{3}|\d)$/.exec(dow);
      if (r && dayOfWeek(r[1]) !== null && dayOfWeek(r[2]) !== null) {
        return `Every ${DAYS[dayOfWeek(r[1])]} through ${DAYS[dayOfWeek(r[2])]} ${at}`;
      }
      return null;
    }
    return `Every ${list(days.map((d) => DAYS[d]))} ${at}`;
  }
  if (any(dow)) {
    const doms = dom.split(',');
    if (dom === 'L') return `On the last day of every month ${at}`;
    if (!doms.every(isInt)) return null;
    return `On the ${list(doms.map((d) => ordinal(Number(d))))} of every month ${at}`;
  }
  return null;
}
