import { apd, h, clear, pageHead, badge, note, field, fgrid, txt, chk, toast, toastErr, confirmBox, copy } from '../ui.js';
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
  const podkopBox = h('div');
  apd(root, pageHead('Компоненты', 'Выбор и установка ядра (sing-box или Mihomo), а также Podkop'), cards, h('div', { style: 'height:14px' }), jobBox, podkopBox);

  // Хватает ли места под установку: свободное место + размер уже стоящей копии (она заменится).
  function space(id) {
    const sg = (S.system && S.system.storage) || {};
    const free = sg.free_mb, need = (sg.need_mb || {})[id] || 0;
    if (free == null || !need) return { ok: true };
    const have = free + ((sg.installed_mb || {})[id] || 0);
    return { ok: free <= 0 || have >= need, free, need, dir: sg.dir };
  }

  function draw() {
    const cores = (S.system && S.system.cores) || {};
    clear(cards);
    for (const id of ['singbox', 'mihomo']) {
      const c = CORES[id], info = cores[id] || {};
      const ver = { v: '' };
      const sel = s.core === id;
      const sp = space(id);
      const lack = !sp.ok;
      const btn = h('button', { class: 'btn primary' + (lack ? ' lowspace' : ''), disabled: lack, title: lack ? 'Не хватает места' : null, onclick: (e) => { e.stopPropagation(); install(id, ver.v); } }, info.installed ? 'Обновить' : 'Установить');
      const pkgBtn = h('button', { class: 'btn', title: 'Ставит пакет из репозитория OpenWrt/Entware (opkg или apk). Сборки из репозитория обычно компактнее релизов GitHub — подходит, если мало свободной памяти.', onclick: (e) => { e.stopPropagation(); install(id, '', 'package'); } }, 'Из пакетов системы');
      const pick = h('input', { type: 'radio', name: 'core', checked: sel, 'aria-label': 'Использовать ' + c.name, onchange: () => { s.core = id; st.touch(); draw(); } });
      cards.append(h('div', { class: 'card corecard' + (sel ? ' sel' : ''), onclick: (e) => { if (e.target.closest('button,input,label')) return; pick.click(); } },
        h('div', { class: 'row' }, h('label', { class: 'row', style: 'cursor:pointer' }, pick, h('b', { style: 'font-size:16px' }, c.name)),
          sel ? badge('выбрано', 'acc') : null, h('span', { class: 'grow' }), info.installed ? badge('установлено', 'ok') : badge('не установлено', 'warn')),
        h('p', { class: 'mute' }, c.tag),
        h('ul', c.pros.map((p) => h('li', p))),
        h('dl', { class: 'kv', style: 'margin:8px 0' }, h('dt', 'Версия'), h('dd', info.version || '—'), h('dt', 'Путь'), h('dd', { class: 'mono' }, info.path || '—')),
        lack ? note('warn', 'Не хватает места в ' + (sp.dir || 'каталоге установки') + ': свободно ' + sp.free + ' МБ, нужно около ' + sp.need + ' МБ. Подключите накопитель и укажите каталог установки ниже (затем сохраните настройки) либо поставьте ядро «Из пакетов системы» — эти сборки компактнее.') : null,
        h('div', { class: 'row' }, h('input', { type: 'text', class: lack ? 'lowspace' : '', disabled: lack, style: 'flex:1;min-width:120px', placeholder: 'версия (пусто — последняя)', 'aria-label': 'Версия ' + c.name, spellcheck: 'false', oninput: (e) => { ver.v = e.target.value.trim(); } }), btn, pkgBtn)));
    }
  }

  async function install(core, version, source) {
    try { await post('api/core/install', { core, version, source: source || 'github' }); } catch (e) { toastErr(e); return; }
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

  // ---------- Podkop ----------
  let pkT = 0;
  async function pkAct(name, confirmText) {
    if (confirmText && !(await confirmBox(confirmText, 'Продолжить', name === 'remove'))) return;
    try { await post('api/podkop/' + name); toast('Готово', 'ok'); } catch (e) { toastErr(e); }
    pkLoad();
  }
  const cmdRow = (title, cmd) => h('div', { style: 'margin:8px 0' }, h('div', { class: 'small mute' }, title),
    h('div', { class: 'row' }, h('code', { class: 'mono grow', style: 'word-break:break-all' }, cmd),
      h('button', { class: 'btn', onclick: () => copy(cmd).then(() => toast('Скопировано', 'ok')) }, 'Копировать')));
  async function pkLoad() {
    clearTimeout(pkT);
    let p;
    try { p = await get('api/podkop'); } catch (e) { if (alive) clear(podkopBox).append(h('div', { class: 'card' }, h('h2', 'Podkop'), note('err', e.message))); return; }
    if (!alive) return;
    const busy = p.job && p.job.running;
    const lack = p.supported && !p.installed && p.free_mb > 0 && p.free_mb < p.need_mb;
    const kids = [h('h2', 'Podkop')];
    if (!p.supported) kids.push(h('p', { class: 'small mute' }, p.reason));
    else {
      kids.push(h('p', { class: 'small mute' }, 'Маршрутизация на базе sing-box для OpenWrt. Это альтернатива ядру панели: вместе они не запускаются (панель это блокирует). Настройки самого Podkop — в LuCI: Службы → Podkop.'));
      kids.push(h('dl', { class: 'kv' }, h('dt', 'Установлен'), h('dd', p.installed ? badge('да', 'ok') : badge('нет', 'warn')),
        h('dt', 'Версия'), h('dd', p.version || '—'),
        h('dt', 'Служба'), h('dd', p.installed ? (p.running ? badge('работает', 'ok') : badge('остановлена')) : '—'),
        h('dt', 'Свободно на флеш'), h('dd', p.free_mb + ' МБ' + (p.installed ? '' : ' (нужно не меньше ' + p.need_mb + ' МБ)'))));
      if (lack) kids.push(note('warn', 'Не хватает места: свободно ' + p.free_mb + ' МБ, для установки нужно не меньше ' + p.need_mb + ' МБ (sing-box ставится как зависимость). Освободите место или подключите накопитель (extroot).'));
      kids.push(p.installed
        ? h('div', { class: 'row', style: 'flex-wrap:wrap;gap:8px;margin-top:10px' },
          h('button', { class: 'btn primary', disabled: busy, onclick: () => pkAct('start') }, 'Запустить'),
          h('button', { class: 'btn', disabled: busy, onclick: () => pkAct('restart') }, 'Перезапустить'),
          h('button', { class: 'btn', disabled: busy, onclick: () => pkAct('stop') }, 'Остановить'),
          h('button', { class: 'btn', disabled: busy, onclick: () => pkAct('enable') }, 'В автозапуск'),
          h('button', { class: 'btn', disabled: busy, onclick: () => pkAct('disable') }, 'Убрать из автозапуска'),
          h('button', { class: 'btn danger', disabled: busy, onclick: () => pkAct('remove', 'Остановить и удалить Podkop (пакеты podkop, luci-app-podkop, luci-i18n-podkop-ru)?') }, 'Удалить'))
        : h('div', { class: 'row install' + (lack ? ' lowspace' : ''), style: 'flex-wrap:wrap;gap:8px;margin-top:10px' },
          h('button', { class: 'btn primary', disabled: busy || lack, onclick: () => pkAct('install', 'Скачать и запустить официальный установщик Podkop с GitHub (itdoginfo/podkop)? Он установит пакеты и зависимости (sing-box) и может удалить конфликтующие пакеты, например https-dns-proxy.') }, 'Установить'),
          h('button', { class: 'btn', disabled: busy || lack, onclick: () => pkAct('install-mirror', 'Установить Podkop через зеркало mirror.podkop.net (если GitHub недоступен)?') }, 'Установить через зеркало')));
      if (!p.installed) kids.push(h('details', { style: 'margin-top:10px' }, h('summary', { class: 'small' }, 'Установить вручную по SSH (если установщик задаёт вопросы)'),
        cmdRow('С GitHub', p.install_cmd), cmdRow('Через зеркало', p.mirror_cmd),
        h('p', { class: 'small mute' }, 'Требуется OpenWrt 24.10 или 25.12. Перед обновлением OpenWrt остановите Podkop.')));
      if (p.job && (p.job.running || p.job.finished)) {
        const pre = h('pre', { class: 'mono', style: 'max-height:300px;overflow:auto;white-space:pre-wrap;margin-top:10px' }, (p.job.output || []).join('\n'));
        kids.push(h('div', { class: 'small', style: 'margin-top:10px' }, h('b', p.job.title || 'Операция')),
          p.job.error ? note('err', p.job.error) : (p.job.finished ? note('ok', 'Завершено') : h('p', { class: 'mute' }, h('span', { class: 'spin' }), 'Выполняется…')), pre);
        setTimeout(() => { pre.scrollTop = pre.scrollHeight; }, 0);
      }
    }
    clear(podkopBox).append(h('div', { class: 'card' }, kids));
    if (busy && alive) pkT = setTimeout(pkLoad, 1500);
  }

  draw();
  pkLoad();
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
      h('div', { class: 'row' }, h('p', { class: 'small mute grow' }, 'Изменения вступают в силу после сохранения настроек. Свободное место считается по сохранённому каталогу.'),
        h('button', { class: 'btn', onclick: async () => { try { await st.loadSystem(); draw(); pkLoad(); toast('Место пересчитано', 'ok'); } catch (e) { toastErr(e); } } }, 'Пересчитать место'))));
  return () => { alive = false; clearTimeout(pollT); clearTimeout(pkT); };
}
