import { apd, h, clear, pageHead, badge, note, chk, toastErr } from '../ui.js';
import { get } from '../api.js';
import * as st from '../state.js';

const LVL = { yes: ['да', 'ok'], partial: ['частично', 'warn'], no: ['нет', 'err'] };
const PANEL = { ui: ['настройки панели', 'acc'], override: ['расширенные добавки', 'warn'], none: ['не настраивается', ''] };

export default async function (root) {
  const core = st.S.settings.core;
  const f = { q: '', only: false };
  const body = h('div');
  let data;
  try { data = await get('api/features'); } catch (e) { apd(root, note('err', 'Справочник недоступен: ' + e.message)); return; }
  const cats = (data && data.categories) || [];
  const cell = (c) => {
    c = c || { level: 'no' };
    const [t, k] = LVL[c.level] || [c.level, ''];
    return [badge(t, k), c.note ? h('div', { class: 'small mute', style: 'margin-top:2px' }, c.note) : null];
  };
  function draw() {
    clear(body);
    const q = f.q.trim().toLowerCase();
    let shown = 0;
    const rows = [];
    for (const c of cats) {
      const items = (c.items || []).filter((it) => {
        if (f.only && (it[core] || { level: 'no' }).level === 'no') return false;
        if (!q) return true;
        return [it.name, it.desc, it.id, c.title, (it.singbox || {}).note, (it.mihomo || {}).note].join(' ').toLowerCase().includes(q);
      });
      if (!items.length) continue;
      rows.push(h('tr', { class: 'cat' }, h('td', { colspan: 4 }, c.title, c.desc ? h('span', { class: 'mute', style: 'text-transform:none;letter-spacing:0;font-family:var(--sans);font-weight:400' }, ' — ' + c.desc) : null)));
      for (const it of items) {
        shown++;
        const p = PANEL[it.panel] || PANEL.none;
        rows.push(h('tr', h('td', h('b', it.name), it.desc ? h('div', { class: 'small mute' }, it.desc) : null),
          h('td', { 'data-l': 'sing-box' }, cell(it.singbox)), h('td', { 'data-l': 'Mihomo' }, cell(it.mihomo)), h('td', { 'data-l': 'В панели' }, badge(p[0], p[1]))));
      }
    }
    if (!shown) { body.append(h('div', { class: 'empty' }, 'Ничего не найдено')); return; }
    body.append(h('div', { class: 'tw' }, h('table', { class: 'ft' },
      h('thead', h('tr', h('th', 'Функция'), h('th', 'sing-box' + (core === 'singbox' ? ' (выбрано)' : '')), h('th', 'Mihomo' + (core === 'mihomo' ? ' (выбрано)' : '')), h('th', 'В панели'))),
      h('tbody', rows))));
  }
  apd(root, pageHead('Справочник функций', 'Что умеет каждое ядро и где это настраивается'),
    h('div', { class: 'row', style: 'margin-bottom:10px' },
      h('input', { type: 'search', style: 'flex:1;min-width:180px;max-width:360px;font:inherit;padding:6px 9px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--ink)', placeholder: 'Поиск по функциям', 'aria-label': 'Поиск', oninput: (e) => { f.q = e.target.value; draw(); } }),
      chk(f, 'only', 'Только то, что есть в выбранном ядре (' + (core === 'mihomo' ? 'Mihomo' : 'sing-box') + ')', null, { onchange: draw })),
    body, h('p', { class: 'small mute', style: 'margin-top:10px' }, '«Расширенные добавки» — ручной JSON в разделе «Конфигурация»: через него доступно то, для чего нет отдельных полей.'));
  draw();
}
