// Редактор списка правил (маршрутизация и DNS) с перетаскиванием.
import { h, clear, sel, lines, txt, help } from './ui.js';
import * as st from './state.js';

export const RULE_TYPES = [
  ['private', 'Локальные сети'], ['geosite', 'geosite (категории доменов)'], ['geoip', 'geoip (страны/сети)'], ['rule_set', 'Набор правил'],
  ['domain', 'Домен (точно)'], ['domain_suffix', 'Домен и поддомены'], ['domain_keyword', 'Домен содержит'], ['domain_regex', 'Домен (regexp)'],
  ['ip_cidr', 'IP / подсеть назначения'], ['src_ip_cidr', 'IP / подсеть источника'], ['port', 'Порт назначения'], ['port_range', 'Диапазон портов'],
  ['network', 'Сеть (tcp/udp)'], ['protocol', 'Протокол (sing-box sniff)'],
];
const DNS_TYPES = ['geosite', 'rule_set', 'domain', 'domain_suffix', 'domain_keyword', 'domain_regex'];
const PH = {
  geosite: 'google\ncategory-ads-all', geoip: 'ru\ncn', rule_set: 'имя набора из списка ниже', domain: 'example.com', domain_suffix: 'example.com\nyoutube.com',
  domain_keyword: 'google', domain_regex: '^ad[0-9]+\\.example\\.com$', ip_cidr: '1.1.1.0/24\n8.8.8.8', src_ip_cidr: '192.168.1.50\n192.168.1.0/28',
  port: '443\n8443', port_range: '1000-2000', network: 'udp', protocol: 'bittorrent\ntls\nquic', private: '',
};
const TIPS = {
  private: 'Адреса 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 и другие локальные. Значения не нужны.',
  geosite: 'Названия категорий из базы geosite (по одному в строке). Нужные наборы скачаются автоматически.',
  geoip: 'Коды стран или категорий из базы geoip (ru, cn, telegram…). Наборы скачаются автоматически.',
  rule_set: 'Имена наборов из раздела «Наборы правил» ниже.',
  port_range: 'Формат 1000-2000, по одному диапазону в строке.',
  protocol: 'Работает только в sing-box и только при включённом sniff. В Mihomo правило будет пропущено.',
};

export function ruleEditor({ rules, outs, dns = false, defaultOut }) {
  const box = h('div');
  let dragFrom = -1;
  const types = dns ? RULE_TYPES.filter((t) => DNS_TYPES.includes(t[0])) : RULE_TYPES;

  function move(i, j) {
    if (j < 0 || j >= rules.length || i === j) return;
    const [r] = rules.splice(i, 1); rules.splice(j, 0, r);
    st.touch(); draw();
  }
  function row(r, i) {
    const o = typeof outs === 'function' ? outs() : outs;
    const el = h('div', { class: 'rule' + (r.disabled ? ' off' : '') });
    const grip = h('span', { class: 'grip', draggable: 'true', title: 'Перетащите, чтобы изменить порядок', 'aria-hidden': 'true' }, '⠿');
    grip.addEventListener('dragstart', (e) => { dragFrom = i; e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', String(i)); try { e.dataTransfer.setDragImage(el, 10, 10); } catch (x) { /* ignore */ } });
    el.addEventListener('dragover', (e) => { if (dragFrom >= 0) { e.preventDefault(); el.classList.add('over'); } });
    el.addEventListener('dragleave', () => el.classList.remove('over'));
    el.addEventListener('drop', (e) => { e.preventDefault(); const f = dragFrom; dragFrom = -1; move(f, i); });
    grip.addEventListener('dragend', () => { dragFrom = -1; box.querySelectorAll('.over').forEach((x) => x.classList.remove('over')); });
    el.append(
      h('div', { class: 'hd' }, grip, h('b', { class: 'mono small' }, '#' + (i + 1)),
        sel(r, 'type', types, { onchange: draw }), h('span', { 'aria-hidden': 'true' }, '→'), sel(r, 'outbound', o),
        TIPS[r.type] ? help(TIPS[r.type]) : null, h('span', { class: 'grow' }),
        h('label', { class: 'check', style: 'margin:0' }, h('input', { type: 'checkbox', checked: !r.disabled, onchange: (e) => { r.disabled = !e.target.checked; st.touch(); el.classList.toggle('off', r.disabled); } }), 'вкл'),
        h('button', { class: 'btn sm', 'aria-label': 'Выше', disabled: i === 0, onclick: () => move(i, i - 1) }, '↑'),
        h('button', { class: 'btn sm', 'aria-label': 'Ниже', disabled: i === rules.length - 1, onclick: () => move(i, i + 1) }, '↓'),
        h('button', { class: 'btn sm danger', 'aria-label': 'Удалить правило', onclick: () => { rules.splice(i, 1); st.touch(); draw(); } }, '✕')),
      h('div', { class: 'bd', style: r.type === 'private' ? 'grid-template-columns:1fr' : null },
        r.type === 'private' ? null : lines(r, 'values', { rows: 2, ph: PH[r.type] || 'по одному значению в строке' }),
        txt(r, 'note', { ph: 'заметка' })));
    return el;
  }
  function draw() {
    clear(box);
    if (!rules.length) box.append(h('div', { class: 'empty' }, 'Правил нет'));
    rules.forEach((r, i) => box.append(row(r, i)));
  }
  draw();
  return {
    el: box,
    add(type = dns ? 'domain_suffix' : 'domain_suffix', outbound) {
      rules.push({ type, values: [], outbound: outbound || (typeof defaultOut === 'function' ? defaultOut() : defaultOut) });
      st.touch(); draw();
    },
    redraw: draw,
  };
}
