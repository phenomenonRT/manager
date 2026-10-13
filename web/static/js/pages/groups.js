import { apd, h, clear, pageHead, badge, note, field, fgrid, txt, num, sel, toast, confirmBox } from '../ui.js';
import * as st from '../state.js';

const S = st.S;
const MODES = {
  fallback: { name: 'Первый рабочий', hint: 'Работает с первым узлом списка, пока он не откажет. После сбоя переходит к следующему рабочему и сам на прежний не возвращается. Порядок в списке задаёт приоритет.' },
  urltest: { name: 'Самый быстрый', hint: 'Ядро периодически замеряет задержку каждого узла и выбирает самый быстрый.' },
  selector: { name: 'Ручной выбор', hint: 'Узел выбираете вы сами: на странице «Обзор» или в дашборде ядра.' },
  loadbalance: { name: 'Распределение', hint: 'Распределяет соединения между узлами. В sing-box не поддерживается и заменяется на «Самый быстрый».' },
};
// Чем проверять узел. Ядро делает HTTP(S)-запрос через узел (ICMP-пинг ядро не умеет).
// Адреса-IP работают, даже если DNS не отвечает.
const PROBES = [
  ['https://www.gstatic.com/generate_204', 'Google (gstatic) — по умолчанию'],
  ['https://cp.cloudflare.com/generate_204', 'Cloudflare'],
  ['https://www.google.com/generate_204', 'Google'],
  ['http://connectivitycheck.gstatic.com/generate_204', 'Google, без HTTPS'],
  ['http://www.msftconnecttest.com/connecttest.txt', 'Microsoft, без HTTPS'],
  ['https://1.1.1.1', 'по IP: Cloudflare 1.1.1.1 (без DNS)'],
  ['https://8.8.8.8', 'по IP: Google 8.8.8.8 (без DNS)'],
];
const CUSTOM = '__custom';
function probePick(g, redraw) {
  const known = PROBES.some((p) => p[0] === (g.url || PROBES[0][0]));
  let custom = !known;
  const input = h('input', { type: 'text', value: g.url || '', placeholder: 'https://example.com/generate_204', spellcheck: 'false', autocomplete: 'off',
    oninput: (e) => { g.url = e.target.value.trim(); st.touch(); } });
  const select = h('select', { 'aria-label': 'Адрес проверки', onchange: (e) => {
    if (e.target.value === CUSTOM) { custom = true; input.parentElement.hidden = false; input.focus(); return; }
    custom = false; g.url = e.target.value; st.touch(); redraw();
  } }, PROBES.map(([v, t]) => h('option', { value: v, selected: !custom && v === (g.url || PROBES[0][0]) }, t)),
    h('option', { value: CUSTOM, selected: custom }, 'Свой адрес…'));
  const box = h('div', { hidden: !custom, style: 'margin-top:6px' }, input);
  return h('div', select, box);
}
const modeOpts = (cur) => Object.keys(MODES).filter((k) => k !== 'loadbalance' || k === cur).map((k) => [k, MODES[k].name]);

export default async function (root) {
  const s = S.settings;
  const top = h('div');
  const list = h('div');
  const more = h('div', { class: 'row', style: 'margin:12px 0' });
  const enabledNodes = () => s.nodes.filter((n) => !n.disabled).map((n) => n.name);
  const taken = (except) => new Set([...s.nodes.map((n) => n.name), ...s.groups.map((g) => g.name), 'direct', 'block'].filter((x) => x !== except));
  const newGroup = (name, type, members) => ({ name, type, members,
    ...(type === 'selector' ? {} : { url: 'https://www.gstatic.com/generate_204', interval: type === 'fallback' ? 60 : 180 }),
    ...(type === 'urltest' ? { tolerance: 50 } : {}) });

  // Одна группа из всех узлов — и она становится основной (Final).
  function create(type) {
    const names = enabledNodes();
    if (!names.length) { toast('Сначала добавьте узлы', 'err'); return; }
    const g = newGroup(st.uniqueName('Proxy', taken()), type, names);
    s.groups.push(g);
    if (s.final === 'direct') s.final = g.name;
    st.touch(); draw();
    toast('Создана группа «' + g.name + '»' + (s.final === g.name ? ' — теперь через неё идёт весь трафик без правил' : ''), 'ok');
  }

  function drawTop() {
    if (!s.groups.length) {
      const opt = (type, title, text, rec) => h('button', { class: 'gopt', type: 'button', onclick: () => create(type) },
        h('b', title, rec ? badge('рекомендуется', 'acc') : null), h('span', { class: 'small mute' }, text));
      clear(top).append(h('div', { class: 'card' }, h('h2', 'Как выбирать узел?'),
        h('p', { class: 'small mute' }, 'Группа объединяет узлы в один выход, через который идёт трафик. Выберите способ — панель создаст одну группу из всех ваших узлов и назначит её основной.'),
        s.nodes.length ? h('div', { class: 'gopts' },
          opt('fallback', 'Первый рабочий', 'Пока первый узел работает — трафик идёт через него; если упал — через следующий.', true),
          opt('urltest', 'Самый быстрый', 'Ядро сравнивает задержку узлов и выбирает лучший.'),
          opt('selector', 'Ручной выбор', 'Узел выбираете вы сами на странице «Обзор».'))
          : note('warn', h('span', 'Узлов пока нет. ', h('a', { href: '#/nodes' }, 'Добавьте узел'), ' — потом вернитесь сюда.'))));
      return;
    }
    const direct = s.final === 'direct';
    const mainOpts = [...s.groups.map((g) => [g.name, 'группа: ' + g.name]), ...s.nodes.map((n) => [n.name, 'узел: ' + n.name]), ['direct', 'direct — напрямую, без прокси']];
    clear(top).append(h('div', { class: 'card gmain' },
      h('label', { class: 'field', style: 'margin:0' }, h('span', { class: 'lbl' }, 'Трафик без правил идёт через'), sel(s, 'final', mainOpts, { onchange: draw })),
      direct ? note('warn', 'Сейчас всё, что не попало под правила, идёт напрямую, мимо VPN. Выберите здесь группу или нажмите «Сделать основной» у нужной группы.') : null));
  }

  function draw() {
    drawTop();
    clear(list);
    s.groups.forEach((g, i) => list.append(card(g, i)));
    clear(more).append(s.groups.length ? h('button', { class: 'btn', onclick: () => {
      s.groups.push(newGroup(st.uniqueName('Группа', taken()), 'fallback', enabledNodes())); st.touch(); draw();
    } }, '+ Ещё одна группа') : null);
  }

  function card(g, i) {
    // кандидаты в участники: узлы, другие группы (кроме тех, что уже содержат эту), direct
    const cands = [...s.nodes.map((n) => n.name), ...s.groups.filter((x) => x !== g && !x.members.includes(g.name)).map((x) => x.name), 'direct'];
    const rest = cands.filter((m) => !g.members.includes(m));
    const kind = (m) => (s.nodes.find((n) => n.name === m) ? s.nodes.find((n) => n.name === m).type : s.groups.some((x) => x.name === m) ? 'группа' : m === 'direct' ? 'напрямую' : '');
    const off = (m) => { const n = s.nodes.find((x) => x.name === m); return n && n.disabled; };
    const nameIn = h('input', {
      type: 'text', value: g.name, 'aria-label': 'Имя группы', spellcheck: 'false',
      onchange: (e) => {
        const n = e.target.value.trim();
        if (!n || taken(g.name).has(n)) { toast('Имя пустое или уже занято', 'err'); e.target.value = g.name; return; }
        st.renameRef(g.name, n); g.name = n; st.touch(); draw();
      },
    });
    const typeSel = sel(g, 'type', modeOpts(g.type), { onchange: () => {
      if (g.type !== 'selector') { g.url = g.url || 'https://www.gstatic.com/generate_204'; if (!g.interval) g.interval = g.type === 'fallback' ? 60 : 180; }
      if (g.type === 'urltest' && !g.tolerance) g.tolerance = 50;
      st.touch(); draw();
    } });
    const add = (m) => { g.members.push(m); st.touch(); draw(); };
    const drop = (m) => { g.members = g.members.filter((x) => x !== m); st.touch(); draw(); };
    const move = (k, d) => { const j = k + d; if (j < 0 || j >= g.members.length) return; [g.members[k], g.members[j]] = [g.members[j], g.members[k]]; st.touch(); draw(); };
    const unknown = g.members.filter((m) => m !== 'block' && !cands.includes(m) && !s.nodes.some((n) => n.name === m) && !s.groups.some((x) => x.name === m));
    const isMain = s.final === g.name;
    const ordered = g.type === 'fallback';

    return h('div', { class: 'card' + (isMain ? ' ismain' : '') },
      h('div', { class: 'row', style: 'margin-bottom:8px;flex-wrap:wrap' },
        h('div', { style: 'flex:1;min-width:150px' }, nameIn), h('div', { style: 'flex:1;min-width:170px' }, typeSel),
        isMain ? badge('основная', 'acc') : h('button', { class: 'btn sm', onclick: () => { s.final = g.name; st.touch(); draw(); toast('Через «' + g.name + '» теперь идёт весь трафик без правил', 'ok'); } }, 'Сделать основной'),
        h('button', { class: 'btn sm', 'aria-label': 'Выше', disabled: i === 0, onclick: () => { [s.groups[i - 1], s.groups[i]] = [s.groups[i], s.groups[i - 1]]; st.touch(); draw(); } }, '↑'),
        h('button', { class: 'btn sm', 'aria-label': 'Ниже', disabled: i === s.groups.length - 1, onclick: () => { [s.groups[i + 1], s.groups[i]] = [s.groups[i], s.groups[i + 1]]; st.touch(); draw(); } }, '↓'),
        h('button', { class: 'btn sm danger', onclick: async () => {
          if (!(await confirmBox('Удалить группу «' + g.name + '»?'))) return;
          s.groups.splice(i, 1); for (const x of s.groups) x.members = x.members.filter((m) => m !== g.name); st.pruneRefs();
          st.touch(); draw();
        } }, 'Удалить')),
      h('p', { class: 'small mute', style: 'margin:0 0 8px' }, (MODES[g.type] || {}).hint || ''),
      g.members.length ? h('ol', { class: 'members' }, g.members.map((m, k) => h('li',
        h('span', { class: 'mono small mute', style: 'min-width:20px' }, String(k + 1)),
        h('span', { class: 'grow' }, m, ' ', h('span', { class: 'small mute' }, kind(m)),
          off(m) ? badge('выключен', 'warn') : null,
          ordered && k === 0 ? badge('основной', 'ok') : null, ordered && k > 0 ? h('span', { class: 'small mute' }, ' запасной') : null),
        h('button', { class: 'btn sm', 'aria-label': 'Выше', disabled: k === 0, onclick: () => move(k, -1) }, '↑'),
        h('button', { class: 'btn sm', 'aria-label': 'Ниже', disabled: k === g.members.length - 1, onclick: () => move(k, 1) }, '↓'),
        h('button', { class: 'btn sm', 'aria-label': 'Убрать из группы', onclick: () => drop(m) }, '✕'))))
        : h('p', { class: 'small', style: 'color:var(--err)' }, 'Группа пуста — добавьте узлы ниже.'),
      unknown.length ? note('err', 'Нет такого узла или группы: ' + unknown.join(', ')) : null,
      rest.length ? h('div', { class: 'addrow' }, h('span', { class: 'small mute' }, 'Добавить:'),
        rest.map((m) => h('button', { class: 'chip', type: 'button', onclick: () => add(m) }, '+ ' + m, ' ', h('small', kind(m))))) : null,
      g.type !== 'selector' ? h('details', { class: 'gset' }, h('summary', 'Параметры проверки'),
        fgrid(
          field('Чем проверять узел', probePick(g, draw), 'Ядро делает запрос по этому адресу через каждый узел и меряет время ответа. Обычный ping (ICMP) ядро не умеет, поэтому используется HTTP(S). Адреса «по IP» работают, даже если DNS не отвечает. Нужен ответ без редиректов, лучше всего подходят адреса generate_204.'),
          field('Интервал, сек', num(g, 'interval', { min: 10 }), 'Как часто проверять узлы. При обрыве реального соединения ядро переключается сразу, не дожидаясь проверки.'),
          g.type === 'urltest' ? field('Допуск, мс', num(g, 'tolerance', { min: 0 }), 'Не переключаться на другой узел, если он быстрее меньше чем на это значение (защита от «дрожания»).') : null)) : null);
  }

  apd(root, pageHead('Группы', 'Группа выбирает, через какой из узлов пойдёт трафик. Обычно хватает одной.'),
    top, list, more);
  draw();
}
