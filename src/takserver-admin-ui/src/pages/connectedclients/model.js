// Helpers for the connected clients page. Field names follow
// SubscriptionApi.SubscriptionInfo (takserver-war .../sync/api/SubscriptionApi.java).

// The server caps /subscriptions/all at this many rows per request
// (SubscriptionApi.MAX_SUBSCRIPTION_PAGE_LIMIT, default 1000).
export const PAGE_LIMIT = 1000;

// Same thresholds as the classic dashboard's health icon.
export function health(sub) {
  const diff = Number(sub.lastReportDiffMilliseconds);
  if (!Number.isFinite(diff) || !sub.lastReportMilliseconds) return { key: 'none', label: 'No reports', color: 'default', rank: 3 };
  if (diff < 10 * 1000) return { key: 'current', label: 'Reporting', color: 'success', rank: 0 };
  if (diff < 3 * 60 * 1000) return { key: 'stale', label: 'Quiet', color: 'warning', rank: 1 };
  return { key: 'dead', label: 'Not reporting', color: 'error', rank: 2 };
}

// Groups arrive as one entry per direction (IN = client can send to it,
// OUT = client receives from it). Merge them per name.
export function mergeGroups(groups) {
  const byName = new Map();
  (Array.isArray(groups) ? groups : []).forEach((g) => {
    if (!g || g.name == null) return;
    const name = String(g.name);
    const e = byName.get(name) || { name, in: false, out: false };
    if (g.direction === 'IN') e.in = true;
    else if (g.direction === 'OUT') e.out = true;
    else { e.in = true; e.out = true; }
    byName.set(name, e);
  });
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function groupDirectionLabel(g) {
  if (g.in && g.out) return 'send and receive';
  if (g.in) return 'send only';
  return 'receive only';
}

export function groupsText(merged) {
  return merged.map((g) => (g.in && g.out ? g.name : `${g.name} (${g.in ? 'send only' : 'receive only'})`)).join(', ');
}

export const str = (v) => (v === null || v === undefined ? '' : String(v));

// Give every row a stable, unique id so selection survives polling.
export function toRows(subs) {
  const list = Array.isArray(subs) ? subs : [];
  const seen = new Set();
  return list.map((s, i) => {
    let id = s.subscriptionUid ? `s:${s.subscriptionUid}` : s.clientUid ? `c:${s.clientUid}` : `i:${i}`;
    while (seen.has(id)) id += `#${i}`;
    seen.add(id);
    const merged = mergeGroups(s.groups);
    return {
      ...s,
      id,
      _health: health(s),
      _groups: merged,
      _groupsText: groupsText(merged),
      _protocol: str(s.protocol) || 'Unknown',
      _endpoint: s.ipAddress ? (s.port ? `${s.ipAddress}:${s.port}` : str(s.ipAddress)) : '',
      _client: [s.takClient, s.takVersion].filter(Boolean).join(' '),
    };
  });
}

const SEARCH_FIELDS = ['callsign', 'username', 'clientUid', 'subscriptionUid', 'ipAddress', 'deviceIPAddress', 'dn'];

export function matches(row, q) {
  if (!q) return true;
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  return SEARCH_FIELDS.some((f) => str(row[f]).toLowerCase().includes(needle));
}

export function formatTime(ms) {
  const n = Number(ms);
  if (!n) return '';
  const d = new Date(n);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString();
}

export function formatAgo(diffMs) {
  const n = Number(diffMs);
  if (!Number.isFinite(n) || n < 0) return '';
  const s = Math.round(n / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

// Static subscription protocols the server can build
// (DistributedSubscriptionManager.initializeStaticSubscription / TransportCotEvent).
export const STATIC_PROTOCOLS = [
  { value: 'tcp', label: 'tcp (TCP, plain CoT)' },
  { value: 'stcp', label: 'stcp (streaming TCP)' },
  { value: 'udp', label: 'udp (UDP unicast)' },
  { value: 'mcast', label: 'mcast (UDP multicast, CoT or protobuf)' },
  { value: 'cotmcast', label: 'cotmcast (UDP multicast, CoT)' },
];

// Every field the server sends, for the detail drawer.
export const DETAIL_SECTIONS = [
  {
    title: 'Identity',
    fields: [
      ['callsign', 'Callsign'], ['username', 'Username'], ['dn', 'Certificate DN'],
      ['clientUid', 'Client UID'], ['subscriptionUid', 'Subscription UID'],
      ['team', 'Team'], ['role', 'Role'],
    ],
  },
  {
    title: 'Connection',
    fields: [
      ['protocol', 'Protocol'], ['ipAddress', 'IP address'], ['port', 'Port'],
      ['lastReportMilliseconds', 'Last report', 'time'], ['pendingWrites', 'Pending writes', 'num'],
      ['numProcessed', 'Messages processed', 'num'], ['xpath', 'XPath filter'], ['incognito', 'Incognito', 'bool'],
      ['handlerType', 'Handler type'],
    ],
  },
  {
    title: 'Device',
    fields: [
      ['takClient', 'TAK client'], ['takVersion', 'Version'], ['deviceIPAddress', 'Device IP address'],
      ['battery', 'Battery'], ['batteryStatus', 'Battery status'], ['batteryTemp', 'Battery temperature'],
      ['appFramerate', 'App frame rate'], ['deviceDataRx', 'Data received'], ['deviceDataTx', 'Data sent'],
      ['heapCurrentSize', 'Heap current'], ['heapFreeSize', 'Heap free'], ['heapMaxSize', 'Heap max'],
      ['storageAvailable', 'Storage available'], ['storageTotal', 'Storage total'],
    ],
  },
];

export function formatField(row, key, kind) {
  const v = row[key];
  if (kind === 'time') return formatTime(v);
  if (kind === 'bool') return v ? 'Yes' : 'No';
  if (kind === 'num') return v === undefined || v === null ? '' : Number(v).toLocaleString();
  return str(v);
}

// Column visibility preference, kept per browser. Storage can be unavailable.
const PREF_KEY = 'takAdmin.connectedClients.columns';
export function loadColumnPrefs(defaults) {
  try {
    const raw = window.localStorage.getItem(PREF_KEY);
    if (!raw) return defaults;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return defaults;
    const out = { ...defaults };
    Object.keys(defaults).forEach((k) => { if (typeof parsed[k] === 'boolean') out[k] = parsed[k]; });
    return out;
  } catch {
    return defaults;
  }
}
export function saveColumnPrefs(model) {
  try { window.localStorage.setItem(PREF_KEY, JSON.stringify(model)); } catch { /* ignore */ }
}
