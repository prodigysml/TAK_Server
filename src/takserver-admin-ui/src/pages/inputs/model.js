// Shared constants, validation and request-body builders for the Inputs page.
// Limits mirror SubmissionApi.getValidationErrors / getDataFeedValidationErrors
// and QoSApi.validateRateLimitRules on the server.

export const NAME_MAX = 30;
export const NAME_RE = /^[A-Za-z0-9_\s]+$/;
export const IFACE_MAX = 15; // classic form limit (server allows 64)
export const IFACE_RE = /^[A-Za-z0-9]+$/;
export const GROUP_RE = /^([0-9]{1,3}\.){3}[0-9]{1,3}$/;
export const FILTERGROUP_MAX_ENTRIES = 64;
export const FILTERGROUP_MAX_LEN = 256;
export const MAX_RATE_RULES = 100; // QoSApi.MAX_RATE_LIMIT_RULES default (-Dtak.qos.maxRules)
export const POLL_MS = 5000;

export const PROTOCOLS = [
  { value: 'tls', label: 'Secure streaming TCP (TLS), CoT or protobuf' },
  { value: 'grpc', label: 'Secure streaming with gRPC, protobuf' },
  { value: 'quic', label: 'Secure streaming with QUIC, CoT or protobuf' },
  { value: 'cottls', label: 'Secure streaming TCP (COTTLS), CoT only' },
  { value: 'stcp', label: 'Streaming TCP (STCP), unencrypted' },
  { value: 'tcp', label: 'Standard TCP, unencrypted' },
  { value: 'udp', label: 'Standard UDP, unencrypted' },
  { value: 'mcast', label: 'Multicast (MCAST)' },
];
// Streaming data feeds: the classic form offers every protocol except QUIC.
export const FEED_PROTOCOLS = PROTOCOLS.filter((p) => p.value !== 'quic');

export const PROTOCOL_SHORT = {
  tls: 'TLS', grpc: 'gRPC', quic: 'QUIC', cottls: 'COTTLS', stcp: 'STCP', tcp: 'TCP', udp: 'UDP',
  mcast: 'Multicast', cotmcast: 'Multicast (CoT)', prototls: 'Proto TLS',
};

export const AUTHS = [
  { value: 'X_509', label: 'X.509 client certificate' },
  { value: 'FILE', label: 'File (username and password)' },
  { value: 'LDAP', label: 'LDAP' },
  { value: 'ANONYMOUS', label: 'None (anonymous)' },
];

// The server may serialize AuthType as the enum name (X_509) or the XML value (x509).
export function normAuth(a) {
  const s = String(a || '').toUpperCase();
  if (s === 'X509' || s === 'X_509') return 'X_509';
  return s;
}
export const AUTH_SHORT = { X_509: 'X.509', FILE: 'File', LDAP: 'LDAP', ANONYMOUS: 'Anonymous' };
export const authLabel = (a) => AUTH_SHORT[normAuth(a)] || String(a || '');

export const TLS_VERSIONS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
export const DEFAULT_TLS = ['TLSv1.2', 'TLSv1.3'];

const ANON_ONLY = ['tcp', 'udp', 'mcast', 'cotmcast'];
const PASSWORD_OK = ['stcp', 'tls', 'prototls', 'cottls'];
export const TLS_PROTOCOLS = ['tls', 'cottls', 'grpc', 'quic', 'prototls'];
export const MCAST_PROTOCOLS = ['mcast', 'cotmcast'];

// Auth types the server accepts for a protocol (SubmissionApi.getValidationErrors).
export function allowedAuths(protocol) {
  return AUTHS.filter((a) => {
    if (ANON_ONLY.includes(protocol)) return a.value === 'ANONYMOUS';
    if (a.value === 'FILE' || a.value === 'LDAP') return PASSWORD_OK.includes(protocol);
    return true;
  });
}

// UDP-based protocols can share a port number with TCP-based ones.
export const transportOf = (p) => (['udp', 'mcast', 'cotmcast', 'quic'].includes(String(p || '').toLowerCase()) ? 'udp' : 'tcp');

export const isTlsProtocol = (p) => TLS_PROTOCOLS.includes(String(p || '').toLowerCase());
export const isMcast = (p) => MCAST_PROTOCOLS.includes(String(p || '').toLowerCase());

// Text area (one entry per line) <-> list.
export const linesToList = (s) => String(s || '').split('\n').map((x) => x.trim()).filter(Boolean);
export const listToLines = (l) => (Array.isArray(l) ? l.join('\n') : '');

export function validateName(name, existingNames) {
  const n = String(name || '').trim();
  if (!n) return 'Enter a name.';
  if (n.length > NAME_MAX) return `Use ${NAME_MAX} characters or fewer.`;
  if (!NAME_RE.test(n)) return 'Use only letters, numbers, spaces and underscores.';
  if (existingNames && existingNames.has(n.toLowerCase())) return 'An input or data feed already uses this name.';
  return null;
}

export function validatePort(port) {
  const s = String(port ?? '').trim();
  if (!s) return 'Enter a port.';
  if (!/^[0-9]+$/.test(s)) return 'Port must be a whole number.';
  const n = Number(s);
  if (n < 1 || n > 65535) return 'Port must be between 1 and 65535.';
  return null;
}

export function validateGroup(group, protocol) {
  const g = String(group || '').trim();
  if (!isMcast(protocol)) return null;
  if (!g) return 'Multicast needs a group address.';
  if (!GROUP_RE.test(g)) return 'Enter an IPv4 address, for example 239.2.3.1.';
  const octets = g.split('.').map(Number);
  if (octets.some((o) => o > 255)) return 'Each part of the address must be 0 to 255.';
  if (octets[0] < 224 || octets[0] > 239) return 'Multicast addresses are in the 224.0.0.0 to 239.255.255.255 range.';
  return null;
}

export function validateIface(iface) {
  const s = String(iface || '').trim();
  if (!s) return null;
  if (s.length > IFACE_MAX) return `Use ${IFACE_MAX} characters or fewer.`;
  if (!IFACE_RE.test(s)) return 'Use only letters and numbers, for example eth0.';
  return null;
}

export function validateFilterGroups(text) {
  const list = linesToList(text);
  if (list.length > FILTERGROUP_MAX_ENTRIES) return `Use ${FILTERGROUP_MAX_ENTRIES} groups or fewer.`;
  if (list.some((x) => x.length > FILTERGROUP_MAX_LEN)) return `Each group must be ${FILTERGROUP_MAX_LEN} characters or fewer.`;
  return null;
}

export function validateRetention(v) {
  const s = String(v ?? '').trim();
  if (!s) return 'Enter a retention time in seconds.';
  if (!/^[0-9]{1,15}$/.test(s)) return 'Use a whole number of seconds.';
  return null;
}

// Each rule: non-negative integers; list: 1..MAX_RATE_RULES (QoSApi.validateRateLimitRules).
export function validateRateRules(rules) {
  if (!rules || rules.length === 0) return 'Add at least one rule. The rate limiter can’t run without one.';
  if (rules.length > MAX_RATE_RULES) return `Use ${MAX_RATE_RULES} rules or fewer.`;
  return null;
}
export function validateRuleValue(v) {
  const s = String(v ?? '').trim();
  if (s === '') return 'Required';
  if (!/^[0-9]+$/.test(s)) return 'Whole number, 0 or more';
  if (Number(s) > 2147483647) return 'Too large';
  return null;
}

// Split the /inputs response into plain inputs and data feeds (feeds carry input.type).
export function splitInputs(list) {
  const inputs = [];
  const feeds = [];
  (Array.isArray(list) ? list : []).forEach((m) => {
    if (!m || !m.input) return;
    if (m.input.type) feeds.push(m);
    else inputs.push(m);
  });
  return { inputs, feeds };
}

export const num = (v) => (typeof v === 'number' ? v : Number(v) || 0);

export function formatBytes(b) {
  const n = num(b);
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export function tlsDisplay(input, secConfig) {
  if (!isTlsProtocol(input?.protocol)) return '';
  if (Number(input.coreVersion) === 2) return input.coreVersion2TlsVersions || '';
  return secConfig?.tlsVersion || '';
}

// Fields accepted by com.bbn.marti.config.DataFeed (CoreConfig.xsd input + dataFeed).
// GET /datafeeds/{name} returns tak.server.feeds.DataFeed, whose list fields are
// named tags/filterGroups, so we map them back and drop fields the PUT doesn't take.
const FEED_PUT_FIELDS = [
  'uuid', 'name', 'type', 'auth', 'authRequired', 'port', 'protocol', 'group', 'iface',
  'archive', 'anongroup', 'archiveOnly', 'coreVersion', 'coreVersion2TlsVersions', 'sync',
  'syncCacheRetentionSeconds', 'federated', 'binaryPayloadWebsocketOnly',
];
export function feedPutBody(feed, changes) {
  const body = {};
  FEED_PUT_FIELDS.forEach((k) => { if (feed[k] !== undefined) body[k] = feed[k]; });
  return {
    ...body,
    filtergroup: feed.filterGroups || [],
    tag: feed.tags || [],
    ...changes,
  };
}
