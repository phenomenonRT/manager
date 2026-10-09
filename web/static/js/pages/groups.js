import { apd, h, clear, pageHead, badge, note, field, fgrid, txt, num, sel, toast, confirmBox } from '../ui.js';
import * as st from '../state.js';

const S = st.S;
const GTYPES = [['selector', 'selector — выбор вручную'], ['urltest', 'urltest — самый быстрый'], ['fallback', 'fallback — первый доступный (Mihomo)'], ['loadbalance', 'loadbalance — распределение (Mihomo)']];
const TYPE_HELP = {
  selector: 'Вы сами выбираете узел на странице «Обзор» (или в дашборде ядра).',
  urltest: 'Ядро периодически проверяет задержку и выбирает самый быстрый узел.',
  fallback: 'Использует первый по порядку доступный узел; при сбое переходит к следующему.',
  loadbalance: 'Распределяет соединения между узлами группы.',
};

export default async function (root) {
  const s = S.settings;
  const list = h('div');
  const top = h('div');

  function taken(except) { return new Set([...s.nodes.map((n) => n.name), ...s.groups.map((g) => g.name), 'direct', 'block'].filter((x) => x !== except)); }

  function draw() {
    clear(top).append(st.isSb(s.core) && s.groups.some((g) => g.type === 'fallback' || g.type === 'loadbalance')
      ? note('warn', 'В sing-box нет групп fallback и loadbalance — они будут заменены на urltest (генератор покажет это в предупреждениях). Для полной поддержки выберите Mihomo.') : '');
    clear(list);
    if (!s.groups.length) list.append(h('div', { class: 'empty' }, 'Групп пока нет. Нажмите «Быстрый старт» или добавьте группу вручную.'));
    s.groups.forEach((g, i) => list.append(card(g, i)));
  }

  function card(g, i) {
    const cands = [...s.nodes.map((n) => n.name), ...s.groups.filter((x) => x !== g).map((x) => x.name), 'direct', 'block'];
    const nameIn = h('input', {
      type: 'text', value: g.name, 'aria-label': 'Имя группы', spellcheck: 'false',
      onchange: (e) => {
        const n = e.target.value.trim();
        if (!n || taken(g.name).has(n)) { toast('Имя пустое или уже занято', 'err'); e.target.value = g.name; return; }
        st.renameRef(g.name, n); g.name = n; st.touch(); draw();
      },
    });
    const typeSel = sel(g, 'type', GTYPES, { onchange: draw });
    const toggle = (m, on) => { if (on) g.members.push(m); else g.members = g.members.filter((x) => x !== m); st.touch(); draw(); };
    const move = (k, d) => { const j = k + d; if (j < 0 || j >= g.members.length) return; [g.members[k], g.members[j]] = [g.members[j], g.members[k]]; st.touch(); draw(); };
    const unknown = g.members.filter((m) => !cands.includes(m));
    return h('div', { class: 'card' },
      h('div', { class: 'row', style: 'margin-bottom:8px' },
        h('div', { style: 'flex:1;min-width:150px' }, nameIn), h('div', { style: 'flex:1;min-width:190px' }, typeSel),
        h('button', { class: 'btn sm', 'aria-label': 'Выше', disabled: i === 0, onclick: () => { [s.groups[i - 1], s.groups[i]] = [s.groups[i], s.groups[i - 1]]; st.touch(); draw(); } }, '↑'),
        h('button', { class: 'btn sm', 'aria-label': 'Ниже', disabled: i === s.groups.length - 1, onclick: () => { [s.groups[i + 1], s.groups[i]] = [s.groups[i], s.groups[i + 1]]; st.touch(); draw(); } }, '↓'),
        h('button', { class: 'btn sm danger', onclick: async () => {
          if (!(await confirmBox('Удалить группу «' + g.name + '»?'))) return;
          s.groups.splice(i, 1); for (const x of s.groups) x.members = x.members.filter((m) => m !== g.name);
          st.touch(); draw();
        } }, 'Удалить')),
      h('p', { class: 'small mute' }, TYPE_HELP[g.type] || ''),
      (g.type !== 'selector') ? fgrid(
        field('URL проверки', txt(g, 'url', { ph: 'https://www.gstatic.com/generate_204' }), 'Адрес, который ядро запрашивает через каждый узел для замера задержки.'),
        field('Интервал, сек', num(g, 'interval', { min: 10 }), 'Как часто проверять задержку. По умолчанию 180.'),
        g.type === 'urltest' ? field('Допуск, мс', num(g, 'tolerance', { min: 0 }), 'Не переключаться на другой узел, если выигрыш по задержке меньше этого значения (защита от «дрожания»).') : null) : null,
      h('div', { class: 'lbl small mute', style: 'margin:4px 0' }, 'Участники (отметьте нужные)'),
      cands.length ? h('div', { class: 'chips' }, cands.map((m) => {
        const on = g.members.includes(m);
        return h('label', { class: 'chip' + (on ? ' on' : '') }, h('input', { type: 'checkbox', checked: on, style: 'accent-color:var(--accent)', onchange: (e) => toggle(m, e.target.checked) }), m);
      })) : null,
      unknown.length ? note('err', 'Нет такого узла или группы: ' + unknown.join(', ')) : null,
      g.members.length ? h('div', [h('div', { class: 'lbl small mute', style: 'margin:10px 0 0' }, 'Порядок'), h('ol', { class: 'members' }, g.members.map((m, k) => h('li',
        h('span', { class: 'grow' }, (k + 1) + '. ' + m),
        h('button', { class: 'btn sm', 'aria-label': 'Выше', disabled: k === 0, onclick: () => move(k, -1) }, '↑'),
        h('button', { class: 'btn sm', 'aria-label': 'Ниже', disabled: k === g.members.length - 1, onclick: () => move(k, 1) }, '↓'),
        h('button', { class: 'btn sm', 'aria-label': 'Убрать', onclick: () => toggle(m, false) }, '✕'))))]) : h('p', { class: 'small', style: 'color:var(--err)' }, 'Группа пуста — добавьте участников.'));
  }

  function quick() {
    const names = s.nodes.filter((n) => !n.disabled).map((n) => n.name);
    if (!names.length) { toast('Сначала добавьте узлы', 'err'); return; }
    const t = taken();
    const auto = st.uniqueName('Auto', t); t.add(auto);
    const proxy = st.uniqueName('Proxy', t);
    s.groups.push({ name: auto, type: 'urltest', members: names.slice(), url: 'https://www.gstatic.com/generate_204', interval: 180, tolerance: 50 });
    s.groups.push({ name: proxy, type: 'selector', members: [auto, ...names] });
    if (s.final === 'direct') s.final = proxy;
    st.touch(); draw(); toast('Созданы группы «' + auto + '» и «' + proxy + '»; «Final» = ' + s.final, 'ok');
  }

  apd(root, pageHead('Группы', 'Объединяют узлы: ручной выбор, автоматический выбор по задержке и т. д.'),
    h('div', { class: 'row', style: 'margin-bottom:12px' },
      h('button', { class: 'btn primary', onclick: () => {
        s.groups.push({ name: st.uniqueName('Группа', taken()), type: 'selector', members: [] }); st.touch(); draw();
      } }, '+ Добавить группу'),
      h('button', { class: 'btn', onclick: quick }, 'Быстрый старт (Auto + Proxy)')),
    top, list);
  draw();
}
