// Thin fetch wrapper for TAK Server's REST API. Same-origin only: every path
// passed in is a fixed server path built by this app, never user-supplied URLs.

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function describe(status, body) {
  if (status === 401 || status === 403) return 'You don’t have permission for this. Sign in with an admin certificate.';
  if (status === 404) return 'Not found on the server.';
  if (status === 413) return 'That upload is larger than the server allows.';
  if (body && typeof body === 'object') {
    const m = body.message || body.error || (Array.isArray(body.messages) && body.messages.join(' '));
    if (m) return String(m).slice(0, 300);
  }
  if (typeof body === 'string' && body.trim() && !body.trim().startsWith('<')) return body.trim().slice(0, 300);
  return `Server returned ${status}.`;
}

async function parse(res) {
  const type = res.headers.get('content-type') || '';
  if (res.status === 204) return null;
  if (type.includes('json')) return res.json();
  const text = await res.text();
  if (type.includes('text/html') && text.includes('<form')) {
    // Session ended and the server served its login page instead of data.
    throw new ApiError(401, 'Your session ended. Reload the page to sign in again.');
  }
  return text;
}

/**
 * request(path, { method, body, query, raw })
 *  - body: plain objects/arrays are sent as JSON; FormData/Blob/string as-is.
 *  - query: object of query parameters (undefined/null values skipped).
 *  - raw: return the parsed body without unwrapping TAK's { data } envelope.
 */
export async function request(path, { method = 'GET', body, query, raw = false, headers = {} } = {}) {
  let url = path;
  if (query) {
    const qs = new URLSearchParams();
    Object.entries(query).forEach(([k, v]) => {
      if (v === undefined || v === null || v === '') return;
      if (Array.isArray(v)) v.forEach((x) => qs.append(k, x));
      else qs.append(k, String(v));
    });
    const s = qs.toString();
    if (s) url += (url.includes('?') ? '&' : '?') + s;
  }
  const init = { method, credentials: 'same-origin', headers: { Accept: 'application/json', ...headers } };
  if (body !== undefined) {
    if (body instanceof FormData || body instanceof Blob || typeof body === 'string') {
      init.body = body;
    } else {
      init.body = JSON.stringify(body);
      init.headers['Content-Type'] = 'application/json';
    }
  }
  let res;
  try {
    res = await fetch(url, init);
  } catch {
    throw new ApiError(0, 'Can’t reach the server. Check your connection and try again.');
  }
  const parsed = await parse(res);
  if (!res.ok) throw new ApiError(res.status, describe(res.status, parsed));
  if (!raw && parsed && typeof parsed === 'object' && !Array.isArray(parsed) && 'data' in parsed) return parsed.data;
  return parsed;
}

export const api = {
  get: (p, o) => request(p, { ...o, method: 'GET' }),
  post: (p, body, o) => request(p, { ...o, method: 'POST', body }),
  put: (p, body, o) => request(p, { ...o, method: 'PUT', body }),
  del: (p, o) => request(p, { ...o, method: 'DELETE' }),
};

// Encode one path segment (ids, names) so it can't change the path.
export const seg = (v) => encodeURIComponent(String(v));
