import { apd, h, clear, pageHead, sel, note, toastErr } from '../ui.js';
import { get } from '../api.js';

const LV = { debug: 0, info: 1, warn: 2, error: 3 };
const ANSI = /\x1b\[[0-9;]*m/g;
function level(line) {
  if (/\b(fatal|panic|error|err)\b/i.test(line)) return 'error';
  if (/\b(warn|warning)\b/i.test(line)) return 'warn';
  if (/\bdebug\b/i.test(line)) return 'debug';
  return 'info';
}
export default async function (root) {
  const f = { level: 'debug', text: '', pause: false, auto: true };
  let all = [], es = null, alive = true;
  const view = h('div', { class: 'log', tabindex: '0', role: 'log', 'aria-label': 'Журнал' });
  const state = h('span', { class: 'small mute' });
  const pass = (l) => LV[l.lv] >= LV[f.level] && (!f.text || l.t.toLowerCase().includes(f.text.toLowerCase()));
  const mk = (l) => h('div', { class: 'lv-' + l.lv }, l.t);
  function redraw() {
    clear(view);
    const frag = document.createDocumentFragment();
    for (const l of all) if (pass(l)) frag.append(mk(l));
    view.append(frag);
    if (!view.firstChild) view.append(h('div', { class: 'mute' }, 'Нет записей'));
    if (f.auto) view.scrollTop = view.scrollHeight;
  }
  function push(t) {
    t = t.replace(ANSI, '');
    const l = { t, lv: level(t) };
    all.push(l);
    if (all.length > 3000) all = all.slice(-2000);
    if (f.pause || !pass(l)) return;
    if (view.firstChild && !view.firstChild.className) clear(view);
    view.append(mk(l));
    while (view.childElementCount > 2000) view.firstChild.remove();
    if (f.auto) view.scrollTop = view.scrollHeight;
  }
  apd(root, pageHead('Логи', 'Журнал ядра в реальном времени'),
    h('div', { class: 'row', style: 'margin-bottom:10px' },
      h('div', { style: 'width:150px' }, sel(f, 'level', [['debug', 'все уровни'], ['info', 'info и выше'], ['warn', 'warn и выше'], ['error', 'только error']], { onchange: redraw })),
      h('input', { type: 'text', style: 'flex:1;min-width:140px;max-width:300px', placeholder: 'Фильтр по тексту', 'aria-label': 'Фильтр по тексту', oninput: (e) => { f.text = e.target.value; redraw(); } }),
      h('label', { class: 'check', style: 'margin:0' }, h('input', { type: 'checkbox', checked: true, onchange: (e) => { f.auto = e.target.checked; if (f.auto) view.scrollTop = view.scrollHeight; } }), 'автопрокрутка'),
      h('button', { class: 'btn', onclick: (e) => { f.pause = !f.pause; e.target.textContent = f.pause ? 'Продолжить' : 'Пауза'; if (!f.pause) redraw(); } }, 'Пауза'),
      h('button', { class: 'btn', onclick: () => { all = []; redraw(); } }, 'Очистить'), state), view);
  try {
    const r = await get('api/logs?n=300');
    all = ((r && r.lines) || []).map((t) => { t = String(t).replace(ANSI, ''); return { t, lv: level(t) }; });
  } catch (e) { toastErr(e); }
  redraw();
  function connect() {
    if (!alive) return;
    es = new EventSource('api/logs/stream');
    es.onopen = () => { state.textContent = '● подключено'; state.style.color = 'var(--ok)'; };
    es.onmessage = (e) => push(e.data);
    es.onerror = () => { state.textContent = '○ нет соединения, повтор…'; state.style.color = 'var(--warn)'; };
  }
  connect();
  return () => { alive = false; if (es) es.close(); };
}
