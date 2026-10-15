import { apd, h, clear, pageHead, note, field, fgrid, txt, num, dur, sel, chk, toast, help } from '../ui.js';
import { ruleEditor } from '../rules.js';
import * as st from '../state.js';
import { transparentNote } from '../transparent.js';

const S = st.S;
const SB = 'https://raw.githubusercontent.com/SagerNet/';
const ID = 'https://raw.githubusercontent.com/itdoginfo/allow-domains/main/';
// [подпись, тип, имя]
const PRESETS = [
  ['Реклама', 'geosite', 'category-ads-all'], ['Россия (домены)', 'geosite', 'category-ru'], ['Россия (IP)', 'geoip', 'ru'],
  ['Локальные (домены)', 'geosite', 'private'], ['Локальные (IP)', 'geoip', 'private'], ['Telegram (домены)', 'geosite', 'telegram'], ['Telegram (IP)', 'geoip', 'telegram'],
  ['YouTube', 'geosite', 'youtube'], ['Google', 'geosite', 'google'], ['Netflix', 'geosite', 'netflix'], ['OpenAI', 'geosite', 'openai'],
  ['Discord', 'geosite', 'discord'], ['GitHub', 'geosite', 'github'], ['Twitter / X', 'geosite', 'twitter'], ['Китай (IP)', 'geoip', 'cn'],
  // обычные текстовые списки itdoginfo/allow-domains: панель сама скачивает и обновляет их
  ['itdoginfo: Россия inside (заблокированное в РФ)', 'list', 'itdog-russia-inside', ID + 'Russia/inside-raw.lst'],
  ['itdoginfo: Россия outside (российское для зарубежья)', 'list', 'itdog-russia-outside', ID + 'Russia/outside-raw.lst'],
  ['itdoginfo: Новости', 'list', 'itdog-news', ID + 'Categories/news.lst'],
  ['itdoginfo: Геоблок', 'list', 'itdog-geoblock', ID + 'Categories/geoblock.lst'],
  ['itdoginfo: Хостинги (Hetzner, OVH, DO, Cloudflare, AWS, Akamai)', 'list', 'itdog-hodca', ID + 'Categories/hodca.lst'],
  ['itdoginfo: Discord', 'list', 'itdog-discord', ID + 'Services/discord.lst'],
  ['itdoginfo: Meta', 'list', 'itdog-meta', ID + 'Services/meta.lst'],
  ['itdoginfo: Telegram', 'list', 'itdog-telegram', ID + 'Services/telegram.lst'],
  ['itdoginfo: TikTok', 'list', 'itdog-tiktok', ID + 'Services/tiktok.lst'],
  ['itdoginfo: Twitter / X', 'list', 'itdog-twitter', ID + 'Services/twitter.lst'],
  ['itdoginfo: YouTube', 'list', 'itdog-youtube', ID + 'Services/youtube.lst'],
  ['itdoginfo: Подсети Cloudflare', 'list', 'itdog-ip-cloudflare', ID + 'Subnets/IPv4/cloudflare.lst'],
  ['itdoginfo: Подсети Discord', 'list', 'itdog-ip-discord', ID + 'Subnets/IPv4/discord.lst'],
  ['itdoginfo: Подсети Meta', 'list', 'itdog-ip-meta', ID + 'Subnets/IPv4/meta.lst'],
  ['itdoginfo: Подсети Telegram', 'list', 'itdog-ip-telegram', ID + 'Subnets/IPv4/telegram.lst'],
  ['itdoginfo: Подсети Twitter / X', 'list', 'itdog-ip-twitter', ID + 'Subnets/IPv4/twitter.lst'],
];
function presetURL(core, kind, name) {
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

  // Набор сам ничего не маршрутизирует: трафик направляет правило «Набор правил → куда». Здесь это правило
  // создаётся и меняется одним выбором «Куда направить», а в списке правил выше оно остаётся видимым.
  const ruleOf = (name) => s.rules.find((x) => x.type === 'rule_set' && x.values && x.values.length === 1 && x.values[0] === name);
  const usedElsewhere = (name) => s.rules.filter((x) => x.type === 'rule_set' && x.values && x.values.includes(name) && !(x.values.length === 1)).length;
  const dest = () => [['', 'не направлять (набор только подключён)'], ...outs()];
  function setRule(name, out) {
    const r = ruleOf(name);
    if (!out) { if (r) s.rules.splice(s.rules.indexOf(r), 1); }
    else if (r) r.outbound = out;
    else s.rules.push({ type: 'rule_set', values: [name], outbound: out });
    st.touch(); ed.redraw();
  }

  function drawSets() {
    clear(setsBox);
    if (!s.rule_sets.length) setsBox.append(h('div', { class: 'empty' }, 'Наборов пока нет. Выберите шаблон выше и укажите, куда направлять трафик из него.'));
    s.rule_sets.forEach((r, i) => {
      let prev = r.name;
      const cur = ruleOf(r.name);
      const more = usedElsewhere(r.name);
      const outSel = h('select', { 'aria-label': 'Куда направить трафик набора ' + r.name, onchange: (e) => { if (!r.name) { toast('Сначала укажите имя набора', 'err'); e.target.value = ''; return; } setRule(r.name, e.target.value); drawSets(); } },
        dest().map(([v, t]) => h('option', { value: v, selected: v === (cur ? cur.outbound : '') }, t)));
      const status = cur ? h('span', { class: 'badge ok' }, 'направляется → ' + cur.outbound)
        : more ? h('span', { class: 'badge' }, 'используется в составном правиле')
          : h('span', { class: 'badge warn' }, 'не используется — трафик не направляется');
      setsBox.append(h('div', { class: 'rule' },
        h('div', { class: 'row', style: 'flex-wrap:wrap;gap:8px 12px;align-items:center;margin-bottom:8px' },
          h('b', r.name || 'новый набор'), status, h('span', { class: 'grow' }),
          h('button', { class: 'btn sm danger', onclick: () => { const old = ruleOf(r.name); if (old) s.rules.splice(s.rules.indexOf(old), 1); s.rule_sets.splice(i, 1); st.touch(); ed.redraw(); drawSets(); } }, 'Удалить')),
        fgrid(field('Куда направить трафик', outSel, 'Создаёт правило «этот набор → выбранный выход». Правила работают сверху вниз: новое добавляется в конец списка правил, а всё, что не подошло, уходит в «Final».'),
          field('Адрес списка (URL)', txt(r, 'url', { ph: 'https://…/set.srs' }), 'Файл .srs или .json — ядро скачивает и обновляет его само. Обычный список (.lst, .txt: домен в строке, можно подсети) панель скачивает и преобразует сама.')),
        h('details', { style: 'margin-top:6px' }, h('summary', { class: 'small' }, 'Дополнительно: имя, формат, обновление'),
          fgrid(field('Имя', txt(r, 'name', { ph: 'my-set', onchange: () => { const c = ruleOf(prev); if (c) c.values = [r.name]; prev = r.name; ed.redraw(); } }), 'Внутреннее имя набора; в правилах он выбирается по нему.'),
            field('Формат', sel(r, 'format', [['', 'определить по URL'], ['srs', 'srs (бинарный)'], ['json', 'json (текстовый)'], ['text', 'список (домен в строке)']]), 'Обычно определяется по окончанию ссылки.'),
            field('Обновлять раз в', dur(r, 'interval', [['сек', 1], ['мин', 60], ['ч', 3600], ['сут', 86400]], { min: 0 }), 'По умолчанию раз в сутки. 0 — значение по умолчанию.')))));
    });
  }

  const presetSel = { v: '0', out: '' };
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
      h('p', { class: 'small mute' }, 'Набор — это готовый список доменов или подсетей (Telegram, YouTube, реклама…). Выберите набор и то, куда направлять его трафик: правило создастся само и появится в списке «Правила» выше. Ссылки на списки (.srs) подставляются автоматически.'),
      h('div', { class: 'row', style: 'margin-bottom:10px;flex-wrap:wrap;gap:8px' },
        h('select', { 'aria-label': 'Шаблон набора', style: 'width:auto', onchange: (e) => { presetSel.v = e.target.value; } }, PRESETS.map((p, i) => h('option', { value: i }, p[0]))),
        h('span', { class: 'small mute' }, '→'),
        h('select', { 'aria-label': 'Куда направить', style: 'width:auto', onchange: (e) => { presetSel.out = e.target.value; } },
          outs().filter((o) => o[0] !== undefined).map(([v, t]) => h('option', { value: v, selected: v === proxyOut() }, t))),
        h('button', { class: 'btn primary', onclick: () => {
          const p = PRESETS[+presetSel.v || 0]; const isList = p[1] === 'list'; const name = isList ? p[2] : p[1] + '-' + p[2];
          if (s.rule_sets.some((r) => r.name === name)) { toast('Набор «' + name + '» уже есть', 'err'); return; }
          const out = presetSel.out || proxyOut();
          s.rule_sets.push(isList ? { name, url: p[3], format: 'text', interval: 86400 } : { name, url: presetURL(core(), p[1], p[2]), format: 'srs', behavior: p[1] === 'geoip' ? 'ipcidr' : 'domain', interval: 86400 });
          setRule(name, out); drawSets(); toast('Добавлен набор «' + p[0] + '» → ' + out, 'ok');
        } }, 'Добавить'),
        h('button', { class: 'btn', onclick: () => { s.rule_sets.push({ name: 'set-' + (s.rule_sets.length + 1), url: '', format: '', behavior: '', interval: 86400 }); st.touch(); drawSets(); } }, 'Свой набор по ссылке')),
      setsBox));
  drawSets();
}
