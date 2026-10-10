import { apd, h, clear, pageHead, note, field, fgrid, txt, num, sel, chk, toast, help } from '../ui.js';
import { ruleEditor } from '../rules.js';
import * as st from '../state.js';
import { transparentNote } from '../transparent.js';

const S = st.S;
const SB = 'https://raw.githubusercontent.com/SagerNet/';
const MC = 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/';
// [подпись, тип, имя]
const PRESETS = [
  ['Реклама', 'geosite', 'category-ads-all'], ['Россия (домены)', 'geosite', 'category-ru'], ['Россия (IP)', 'geoip', 'ru'],
  ['Локальные (домены)', 'geosite', 'private'], ['Локальные (IP)', 'geoip', 'private'], ['Telegram (домены)', 'geosite', 'telegram'], ['Telegram (IP)', 'geoip', 'telegram'],
  ['YouTube', 'geosite', 'youtube'], ['Google', 'geosite', 'google'], ['Netflix', 'geosite', 'netflix'], ['OpenAI', 'geosite', 'openai'],
  ['Discord', 'geosite', 'discord'], ['GitHub', 'geosite', 'github'], ['Twitter / X', 'geosite', 'twitter'], ['Китай (IP)', 'geoip', 'cn'],
];
function presetURL(core, kind, name) {
  if (core === 'mihomo') return MC + kind + '/' + name + '.mrs';
  return SB + (kind === 'geosite' ? 'sing-geosite/rule-set/geosite-' : 'sing-geoip/rule-set/geoip-') + name + '.srs';
}
// быстрые шаблоны правил: [подпись, тип, значения, куда]
const QUICK = [
  ['Локальные сети → напрямую', 'private', [], 'direct'], ['Реклама → блок', 'geosite', ['category-ads-all'], 'block'],
  ['Россия → напрямую', 'geosite', ['category-ru'], 'direct'], ['Россия (IP) → напрямую', 'geoip', ['ru'], 'direct'],
  ['Telegram → прокси', 'geosite', ['telegram'], '@proxy'], ['YouTube → прокси', 'geosite', ['youtube'], '@proxy'],
];

export default async function (root) {
  const s = S.settings;
  const outs = () => st.outbounds();
  const proxyOut = () => (s.groups.find((g) => g.type === 'selector') || s.groups[0] || s.nodes[0] || { name: 'direct' }).name;
  const ed = ruleEditor({ rules: s.rules, outs, defaultOut: proxyOut });
  const setsBox = h('div');
  const core = () => s.core;

  function drawSets() {
    clear(setsBox);
    if (!s.rule_sets.length) setsBox.append(h('div', { class: 'empty' }, 'Своих наборов нет. Для типов geosite/geoip наборы подключаются автоматически.'));
    s.rule_sets.forEach((r, i) => setsBox.append(h('div', { class: 'rule' },
      fgrid(field('Имя', txt(r, 'name', { ph: 'my-set' }), 'Это имя вы указываете в правиле типа «Набор правил».'),
        field('URL', txt(r, 'url', { ph: 'https://…/set.srs' })),
        field('Формат', sel(r, 'format', [['', 'определить по URL'], ['srs', 'srs (sing-box)'], ['json', 'json (sing-box)'], ['mrs', 'mrs (Mihomo)'], ['yaml', 'yaml (Mihomo)'], ['text', 'text (Mihomo)']]), 'sing-box понимает srs/json, Mihomo — mrs/yaml/text. Набор не того формата будет пропущен.'),
        field('Behavior (Mihomo)', sel(r, 'behavior', [['', 'авто'], 'domain', 'ipcidr', 'classical']), 'Что внутри набора: домены, подсети или смешанные правила. Нужно только Mihomo.'),
        field('Обновлять, сек', num(r, 'interval', { min: 0 }), '86400 = раз в сутки. 0 — по умолчанию.')),
      h('div', { class: 'row end' }, h('button', { class: 'btn sm danger', onclick: () => { s.rule_sets.splice(i, 1); st.touch(); drawSets(); } }, 'Удалить')))));
  }

  const presetSel = { v: '0' };
  const g = s.general;
  apd(root, pageHead('Маршрутизация', 'Правила применяются сверху вниз: побеждает первое подходящее'), transparentNote(),
    h('div', { class: 'card' }, h('h2', 'Общее'),
      fgrid(field('Final — исходящий по умолчанию', sel(s, 'final', outs()), 'Куда отправлять трафик, не попавший ни под одно правило.'),
        field('Скачивать наборы правил через', sel(g, 'update_via', [['direct', 'direct — напрямую'], ...outs().filter((o) => o[0] !== 'direct' && o[0] !== 'block')]), 'Если GitHub заблокирован, укажите здесь рабочий узел или группу.')),
      chk(g, 'bypass_lan', 'Локальные сети — напрямую (bypass LAN)', 'Добавляет правило «частные адреса → direct» перед остальными, чтобы доступ к роутеру и устройствам дома не уходил в прокси.'),
      chk(g, 'sniff', 'Определять домен и протокол (sniff)', 'Ядро подсматривает SNI/Host в первых пакетах. Нужно для доменных правил при прозрачном прокси и для правил по протоколу.')),
    h('div', { class: 'card' }, h('h2', 'Правила'),
      h('div', { class: 'row', style: 'margin-bottom:10px' },
        h('button', { class: 'btn primary', onclick: () => ed.add() }, '+ Добавить правило'),
        h('select', { 'aria-label': 'Шаблон правила', style: 'width:auto', onchange: (e) => {
          const q = QUICK[e.target.value]; e.target.value = ''; if (!q) return;
          s.rules.push({ type: q[1], values: q[2].slice(), outbound: q[3] === '@proxy' ? proxyOut() : q[3] }); st.touch(); ed.redraw();
        } }, h('option', { value: '' }, 'Добавить по шаблону…'), QUICK.map((q, i) => h('option', { value: i }, q[0])))),
      ed.el),
    h('div', { class: 'card' }, h('h2', 'Наборы правил'),
      h('p', { class: 'small mute' }, 'Удалённые списки доменов и подсетей. Шаблоны ниже подставят ссылки ' + (core() === 'mihomo' ? 'MetaCubeX meta-rules-dat (.mrs)' : 'SagerNet sing-geosite/sing-geoip (.srs)') + ' под текущее ядро.'),
      h('div', { class: 'row', style: 'margin-bottom:10px' },
        h('select', { 'aria-label': 'Шаблон набора', style: 'width:auto', onchange: (e) => { presetSel.v = e.target.value; } }, PRESETS.map((p, i) => h('option', { value: i }, p[0] + ' — ' + p[1] + '-' + p[2]))),
        h('button', { class: 'btn', onclick: () => {
          const p = PRESETS[+presetSel.v || 0]; const name = p[1] + '-' + p[2];
          if (s.rule_sets.some((r) => r.name === name)) { toast('Набор «' + name + '» уже есть', 'err'); return; }
          s.rule_sets.push({ name, url: presetURL(core(), p[1], p[2]), format: core() === 'mihomo' ? 'mrs' : 'srs', behavior: p[1] === 'geoip' ? 'ipcidr' : 'domain', interval: 86400 });
          st.touch(); drawSets(); toast('Добавлен набор «' + name + '». Используйте его в правиле типа «Набор правил».', 'ok');
        } }, 'Добавить набор'),
        h('button', { class: 'btn', onclick: () => { s.rule_sets.push({ name: '', url: '', format: '', behavior: '', interval: 86400 }); st.touch(); drawSets(); } }, 'Свой набор')),
      setsBox));
  drawSets();
}
