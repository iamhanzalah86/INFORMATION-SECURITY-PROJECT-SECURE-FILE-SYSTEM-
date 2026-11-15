/**
 * Talks to the Flask JSON API (app/api.py).
 * - Same-origin requests with the session cookie (Vite proxies /api to Flask in dev;
 *   Flask serves the built app in production).
 * - CSRF protection stays on: the token comes from GET /api/csrf and is sent as X-CSRFToken.
 */
let csrfToken = null;

async function loadCsrf(force = false) {
  if (!csrfToken || force) {
    const res = await fetch('/api/csrf', { credentials: 'same-origin' });
    csrfToken = (await res.json()).token;
  }
  return csrfToken;
}

function apiError(res, data) {
  const e = new Error((data && data.error) || `Request failed (${res.status})`);
  e.status = res.status;
  e.data = data || {};
  return e;
}

async function parse(res) {
  try { return await res.json(); } catch (e) { return null; }
}

async function request(method, url, { json, form } = {}, retry = true) {
  const headers = { Accept: 'application/json' };
  let body;
  if (method !== 'GET') headers['X-CSRFToken'] = await loadCsrf();
  if (json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(json); }
  else if (form) body = form;

  const res = await fetch(url, { method, headers, body, credentials: 'same-origin' });
  const data = await parse(res);

  if (res.status === 400 && data && data.csrf && retry) {
    await loadCsrf(true);
    return request(method, url, { json, form }, false);
  }
  if (res.status === 401 && data && data.unauthorized) {
    window.dispatchEvent(new Event('sv:unauthorized'));
  }
  if (!res.ok) throw apiError(res, data);
  return data;
}

const get = (url) => request('GET', url);
const post = (url, json = {}) => request('POST', url, { json });

export const api = {
  me: () => get('/api/me'),

  // auth
  login: (d) => post('/api/login', d),
  logout: () => post('/api/logout'),
  register: (d) => post('/api/register', d),
  verifyStatus: () => get('/api/verify-email'),
  verifyEmail: (d) => post('/api/verify-email', d),
  verifyResend: () => post('/api/verify-email/resend'),
  forgotPassword: (d) => post('/api/forgot-password', d),
  resetStatus: () => get('/api/reset-password'),
  resetPassword: (d) => post('/api/reset-password', d),
  resetResend: () => post('/api/reset-password/resend'),

  // vault
  getDashboard: () => get('/api/dashboard'),
  uploadFile: (file) => {
    const form = new FormData();
    form.append('file', file);
    return request('POST', '/api/upload', { form });
  },
  integrityScan: () => post('/api/integrity-scan'),
  deleteFile: (id) => request('DELETE', `/api/files/${id}`),
  devTamper: (id) => post(`/api/dev/tamper/${id}`),
  getEvents: () => get('/api/security-events').then((d) => d.events),

  // download: verified + decrypted by the server, then saved by the browser
  async downloadFile(id, fallbackName = 'download') {
    const res = await fetch(`/api/files/${id}/download`, { credentials: 'same-origin' });
    if (!res.ok) throw apiError(res, await parse(res));
    const disposition = res.headers.get('Content-Disposition') || '';
    const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition);
    const name = match ? decodeURIComponent(match[1]) : fallbackName;
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },

  // recovery (password -> emailed code)
  getFile: (id) => get(`/api/files/${id}`).then((d) => d.file),
  recoverStart: (id, d) => post(`/api/files/${id}/recover`, d),
  recoverVerify: (id, d) => post(`/api/files/${id}/recover/verify`, d),
};
