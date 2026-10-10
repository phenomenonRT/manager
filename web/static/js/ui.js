// Помощники построения DOM, тосты, модальные окна, привязанные поля форм.
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  if (attrs !== null && attrs !== undefined && (typeof attrs !== 'object' || attrs instanceof Node || Array.isArray(attrs))) {
    kids.unshift(attrs); attrs = null;
  }
  const props = [];
  if (attrs) {
    for (const k of Object.keys(attrs)) {
      const v = attrs[k];
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'value' || k === 'checked' || k === 'disabled' || k === 'selected') props.push([k, v]);
      else el.setAttribute(k, v === true ? '' : v);
    }
  }
  add(el, kids);
  for (const [k, v] of props) el[k] = v;
  return el;
}
function add(el, kids) {
  for (const c of kids) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) add(el, c);
    else el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}
// clear(el).append(...) безопасно пропускает null/false (нативный append печатает «null»).
export const clear = (el) => { el.replaceChildren(); return { append: (...k) => { add(el, k); return el; } }; };
export const apd = (el, ...k) => { add(el, k); return el; };
export const $ = (s, r = document) => r.querySelector(s);

// ---- форматирование ----
export function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(n < 10 ? 2 : 1) : n) + ' ' + u[i];
}
export function fmtDur(sec) {
  sec = Math.max(0, Math.floor(Number(sec) || 0));
  const d = Math.floor(sec / 86400), hh = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
  if (d) return d + ' д ' + hh + ' ч';
  if (hh) return hh + ' ч ' + m + ' мин';
  if (m) return m + ' мин ' + s + ' с';
  return s + ' с';
}

// ---- тосты ----
export function toast(msg, kind = '', ms = 4200) {
  const box = document.getElementById('toasts');
  const t = h('div', { class: 'toast ' + kind, role: kind === 'err' ? 'alert' : 'status' }, h('span', { class: 'tmsg' }, msg),
    h('button', { type: 'button', class: 'xbtn', 'aria-label': 'Закрыть', onclick: () => t.remove() }, '×'));
  box.append(t);
  setTimeout(() => t.remove(), kind === 'err' ? Math.max(ms, 25000) : ms); // ошибки висят 25 с
}
export const errMsg = (e) => (e && e.message) || String(e);
export const toastErr = (e) => { if (!e || e.name !== 'AbortError') toast(errMsg(e), 'err'); };

// ---- модальные окна ----
export function modal({ title, body, buttons = [], wide = false, onclose }) {
  const dlg = h('dialog', { class: wide ? 'wide' : '' });
  const close = () => { if (dlg.open) dlg.close(); };
  const bar = buttons.map((b) => h('button', {
    type: 'button', class: 'btn' + (b.primary ? ' primary' : '') + (b.danger ? ' danger' : ''),
    onclick: async () => { const r = b.onclick ? await b.onclick(close) : undefined; if (r !== false && !b.keep) close(); },
  }, b.text));
  const form = h('form', { method: 'dialog', onsubmit: (e) => e.preventDefault() },
    h('div', { class: 'mh' }, title), h('div', { class: 'mb', tabindex: '-1' }, body), h('div', { class: 'mf' }, bar));
  dlg.append(form);
  dlg.addEventListener('close', () => { dlg.remove(); if (onclose) onclose(); });
  dlg.addEventListener('mousedown', (e) => { if (e.target === dlg) close(); });
  document.body.append(dlg);
  dlg.showModal();
  const f0 = dlg.querySelector('input:not([type=checkbox]):not([type=radio]),select,textarea');
  if (f0 && matchMedia('(pointer:fine)').matches) f0.focus(); else dlg.querySelector('.mb').focus();
  return { close, el: dlg };
}
export function confirmBox(msg, okText = 'Удалить', danger = true) {
  return new Promise((res) => {
    let done = false;
    const fin = (v) => { if (!done) { done = true; res(v); } };
    modal({
      title: 'Подтверждение', body: h('p', msg), onclose: () => fin(false),
      buttons: [{ text: 'Отмена' }, { text: okText, primary: !danger, danger, onclick: () => { fin(true); } }],
    });
  });
}

// ---- поля ----
let editHook = () => {};
export const onEdit = (f) => { editHook = f; };
const fire = (o) => { editHook(); if (o && o.onchange) o.onchange(); };

export function help(text) {
  return h('span', { class: 'help', tabindex: '0', role: 'img', 'aria-label': text, 'data-tip': text }, '?');
}
export function field(label, control, tip) {
  return h('label', { class: 'field' }, h('span', { class: 'lbl' }, label, tip ? help(tip) : null), control);
}
export function fgrid(...c) { return h('div', { class: 'fgrid' }, c); }

export function txt(obj, key, o = {}) {
  return h('input', {
    type: o.type || 'text', value: obj[key] ?? '', placeholder: o.ph, autocomplete: 'off', spellcheck: 'false', list: o.list,
    oninput: (e) => { obj[key] = e.target.value; fire(o); },
  });
}
export function num(obj, key, o = {}) {
  return h('input', {
    type: 'number', value: obj[key] ?? 0, min: o.min, max: o.max, placeholder: o.ph, inputmode: 'numeric',
    oninput: (e) => { const v = parseInt(e.target.value, 10); obj[key] = Number.isFinite(v) ? v : 0; fire(o); },
  });
}
export function pw(obj, key, o = {}) {
  const i = txt(obj, key, { ...o, type: 'password' });
  const b = h('button', {
    type: 'button', class: 'btn sm', 'aria-label': 'Показать или скрыть', title: 'Показать/скрыть',
    onclick: () => { const s = i.type === 'password'; i.type = s ? 'text' : 'password'; b.textContent = s ? 'скрыть' : 'показать'; },
  }, 'показать');
  return h('div', { class: 'pw' }, i, b, o.extra);
}
export function area(obj, key, o = {}) {
  return h('textarea', {
    rows: o.rows || 3, placeholder: o.ph, spellcheck: 'false', value: obj[key] ?? '',
    oninput: (e) => { obj[key] = e.target.value; fire(o); },
  });
}
export function lines(obj, key, o = {}) {
  return h('textarea', {
    rows: o.rows || 3, placeholder: o.ph, spellcheck: 'false', value: (obj[key] || []).join('\n'),
    oninput: (e) => { obj[key] = e.target.value.split('\n').map((s) => s.trim()).filter(Boolean); fire(o); },
  });
}
export function csv(obj, key, o = {}) {
  return h('input', {
    type: 'text', placeholder: o.ph, spellcheck: 'false', autocomplete: 'off', value: (obj[key] || []).join(', '),
    oninput: (e) => { obj[key] = e.target.value.split(',').map((s) => s.trim()).filter(Boolean); fire(o); },
  });
}
// opts: ['a','b'] или [['a','Метка'], ...]
export function sel(obj, key, opts, o = {}) {
  const list = opts.map((x) => (Array.isArray(x) ? x : [x, x || '—']));
  const cur = obj[key] ?? '';
  if (!list.some((x) => x[0] === cur)) list.push([cur, cur + ' (нет такого)']);
  return h('select', { value: cur, onchange: (e) => { obj[key] = e.target.value; fire(o); } },
    list.map(([v, t]) => h('option', { value: v, selected: v === cur }, t)));
}
export function chk(obj, key, label, tip, o = {}) {
  return h('label', { class: 'check' },
    h('input', { type: 'checkbox', checked: !!obj[key], onchange: (e) => { obj[key] = e.target.checked; fire(o); } }),
    h('span', label, tip ? help(tip) : null));
}
// Ошибка с крестиком: закрытая ошибка не показывается снова, пока её текст не изменится.
const dismissed = new Set();
export function errNote(...c) {
  const el = h('div', { class: 'note err closable', role: 'alert' });
  const body = h('div', { class: 'nbody' }, c);
  el.append(body);
  const key = body.textContent;
  if (dismissed.has(key)) el.hidden = true;
  el.append(h('button', { type: 'button', class: 'xbtn', 'aria-label': 'Закрыть', onclick: () => { dismissed.add(key); el.hidden = true; } }, '×'));
  return el;
}
export const note = (kind, ...c) => h('div', { class: 'note ' + kind, role: kind === 'err' ? 'alert' : null }, c);
export const badge = (text, kind = '') => h('span', { class: 'badge ' + kind }, text);
export const spinner = (t = 'Загрузка…') => h('p', { class: 'mute' }, h('span', { class: 'spin' }), t);
export function pageHead(title, desc) {
  return h('div', { class: 'pagehead' }, h('h1', title), desc ? h('p', desc) : null);
}

// скачивание / копирование
export function download(name, text, type = 'application/json') {
  const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: type + ';charset=utf-8' })), download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
export async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('Скопировано', 'ok', 1800); return; } catch (e) { /* запасной путь */ }
  const t = h('textarea', { value: text, style: 'position:fixed;opacity:0' });
  document.body.append(t); t.select();
  try { document.execCommand('copy'); toast('Скопировано', 'ok', 1800); } catch (e) { toast('Не удалось скопировать', 'err'); }
  t.remove();
}
