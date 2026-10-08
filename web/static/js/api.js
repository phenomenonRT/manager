// Тонкая обёртка над fetch: JSON, cookie-сессия, заголовок CSRF-защиты.
let authHandler = () => {};
export const setAuthHandler = (f) => { authHandler = f; };

export class ApiError extends Error {
  constructor(msg, status) { super(msg); this.status = status; }
}

export async function api(method, path, body, opts = {}) {
  const init = { method, credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: opts.signal };
  if (method !== 'GET') init.headers['X-Requested-With'] = 'corepanel';
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try { res = await fetch(path, init); }
  catch (e) {
    if (e.name === 'AbortError') throw e;
    throw new ApiError('Нет связи с панелью', 0);
  }
  const txt = await res.text();
  let data = null;
  if (txt) { try { data = JSON.parse(txt); } catch (e) { data = txt; } }
  if (!res.ok) {
    if (res.status === 401 && !opts.noAuth) authHandler();
    const msg = (data && data.error) || (typeof data === 'string' && data.slice(0, 200)) || res.statusText || ('HTTP ' + res.status);
    throw new ApiError(msg, res.status);
  }
  return data;
}
export const get = (p, o) => api('GET', p, undefined, o);
export const post = (p, b, o) => api('POST', p, b === undefined ? {} : b, o);
export const put = (p, b, o) => api('PUT', p, b, o);

// Потоковый JSON «по объекту в строке» (Clash /traffic).
export async function streamJSON(path, onObj, signal) {
  const res = await fetch(path, { credentials: 'same-origin', signal });
  if (!res.ok || !res.body) throw new ApiError('HTTP ' + res.status, res.status);
  const rd = res.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  for (;;) {
    const { done, value } = await rd.read();
    if (done) return;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) { try { onObj(JSON.parse(line)); } catch (e) { /* пропускаем мусор */ } }
    }
  }
}
