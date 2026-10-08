import { apd, h, clear, pageHead, badge, note, field, fgrid, txt, chk, toast, toastErr } from '../ui.js';
import { get, post } from '../api.js';
import * as st from '../state.js';

const S = st.S;
const CORES = {
  singbox: {
    name: 'sing-box', tag: 'универсальный и экономичный',
    pros: ['Современная модель маршрутизации: sniff, rule-set (.srs), правила по протоколу', 'Встроенный WireGuard, возможность создать системный интерфейс', 'TUN с auto_redirect (nftables) — прозрачный прокси без лишних правил', 'Reality, Hysteria2, TUIC, ShadowTLS; обычно меньше расходует память'],
  },
  mihomo: {
    name: 'Mihomo', tag: 'Clash.Meta, богатые группы',
    pros: ['Группы fallback и load-balance, провайдеры прокси', 'Совместимость с Clash-дашбордами (zashboard, metacubexd)', 'Наборы правил .mrs/yaml, fake-ip, sniffer, TUN', 'Простой YAML-конфиг; много готовых правил MetaCubeX'],
  },
};

export default async function (root) {
  const s = S.settings;
  let alive = true, pollT = 0;
  const cards = h('div', { class: 'cols' });
  const jobBox = h('div');
  apd(root, pageHead('Ядро', 'Какой движок будет обрабатывать трафик, и установка его бинарного файла'), cards, h('div', { style: 'height:14px' }), jobBox);

  function draw() {
    const cores = (S.system && S.system.cores) || {};
    clear(cards);
    for (const id of ['singbox', 'mihomo']) {
      const c = CORES[id], info = cores[id] || {};
      const ver = { v: '' };
      const sel = s.core === id;
      const btn = h('button', { class: 'btn primary', onclick: (e) => { e.stopPropagation(); install(id, ver.v); } }, info.installed ? 'Обновить' : 'Установить');
      const pick = h('input', { type: 'radio', name: 'core', checked: sel, 'aria-label': 'Использовать ' + c.name, onchange: () => { s.core = id; st.touch(); draw(); } });
      cards.append(h('div', { class: 'card corecard' + (sel ? ' sel' : ''), onclick: (e) => { if (e.target.closest('button,input,label')) return; pick.click(); } },
        h('div', { class: 'row' }, h('label', { class: 'row', style: 'cursor:pointer' }, pick, h('b', { style: 'font-size:16px' }, c.name)),
          sel ? badge('выбрано', 'acc') : null, h('span', { class: 'grow' }), info.installed ? badge('установлено', 'ok') : badge('не установлено', 'warn')),
        h('p', { class: 'mute' }, c.tag),
        h('ul', c.pros.map((p) => h('li', p))),
        h('dl', { class: 'kv', style: 'margin:8px 0' }, h('dt', 'Версия'), h('dd', info.version || '—'), h('dt', 'Путь'), h('dd', { class: 'mono' }, info.path || '—')),
        h('div', { class: 'row' }, h('input', { type: 'text', style: 'flex:1;min-width:120px', placeholder: 'версия (пусто — последняя)', 'aria-label': 'Версия ' + c.name, spellcheck: 'false', oninput: (e) => { ver.v = e.target.value.trim(); } }), btn)));
    }
  }

  async function install(core, version) {
    try { await post('api/core/install', { core, version }); } catch (e) { toastErr(e); return; }
    toast('Загрузка начата', 'ok'); poll();
  }
  function poll() {
    clearTimeout(pollT);
    const tick = async () => {
      if (!alive) return;
      let j;
      try { j = await get('api/core/job'); } catch (e) { return; }
      drawJob(j);
      if (j && j.running) { pollT = setTimeout(tick, 700); return; }
      if (j && j.finished) {
        if (j.error) toast('Ошибка установки: ' + j.error, 'err'); else toast('Установлено: ' + (j.version || ''), 'ok');
        try { await st.loadSystem(); } catch (e) { /* ignore */ }
        if (alive) draw();
      }
    };
    tick();
  }
  function drawJob(j) {
    clear(jobBox);
    if (!j || (!j.running && !j.finished && !j.stage)) return;
    const bar = h('i'); bar.style.width = Math.min(100, j.percent || 0) + '%';
    jobBox.append(h('div', { class: 'card' }, h('h2', 'Установка ' + (j.core === 'mihomo' ? 'Mihomo' : j.core === 'singbox' ? 'sing-box' : '')),
      j.error ? note('err', j.error) : null,
      h('div', { class: 'row small', style: 'margin-bottom:6px' }, j.running ? h('span', { class: 'spin' }) : null, h('span', j.message || j.stage || ''), h('span', { class: 'grow' }), h('span', (j.percent || 0) + '%')),
      h('div', { class: 'progress', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(j.percent || 0) }, bar)));
  }

  draw();
  get('api/core/job').then((j) => { if (j && j.running) poll(); else drawJob(j && j.finished && j.error ? j : null); }).catch(() => {});

  const d = s.download;
  apd(root, 
    h('div', { class: 'card' }, h('h2', 'Автозапуск'),
      chk(s, 'autostart', 'Запускать ядро вместе с панелью', 'При старте роутера панель сама поднимет выбранное ядро с сохранёнными настройками.')),
    h('div', { class: 'card' }, h('h2', 'Загрузка ядер и наборов правил'),
      note('', 'Релизы берутся с GitHub. Если GitHub недоступен, укажите зеркало или прокси.'),
      fgrid(
        field('Зеркало GitHub', txt(d, 'mirror', { ph: 'https://ghfast.top/' }), 'Префикс, который добавляется перед ссылкой на GitHub. Используется для ядер и наборов правил.'),
        field('HTTP-прокси для загрузок', txt(d, 'proxy', { ph: 'http://127.0.0.1:7890' }), 'Например, mixed-порт уже работающего ядра или другого прокси. Формат: http(s)://host:port.'),
        field('Каталог установки ядер', txt(d, 'bin_dir', { ph: (S.system && S.system.platform && S.system.platform.bin_dir) || '/opt/bin' }), 'Куда класть бинарники. Пусто — каталог по умолчанию для платформы. На роутерах с малой флеш-памятью выбирайте внешний накопитель.'),
        field('Свой бинарник sing-box', txt(d, 'singbox_path', { ph: '/opt/bin/sing-box' }), 'Если указан, используется он, а не скачанный панелью. Полезно для сборок с нужными тегами.'),
        field('Свой бинарник Mihomo', txt(d, 'mihomo_path', { ph: '/opt/bin/mihomo' }))),
      h('p', { class: 'small mute' }, 'Изменения вступают в силу после сохранения настроек.')));
  return () => { alive = false; clearTimeout(pollT); };
}
