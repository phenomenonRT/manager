import { apd, h, clear, pageHead, badge, note, field, fgrid, txt, chk, toast, toastErr, confirmBox } from '../ui.js';
import { get, post } from '../api.js';
import * as st from '../state.js';

const S = st.S;
const CORES = {
  singbox: { name: 'sing-box', tag: 'Универсальное и экономное ядро', chips: ['sniff и rule-set', 'WireGuard', 'TUN auto_redirect', 'Reality, Hysteria2, TUIC'], pkg: true },
  mihomo: { name: 'Mihomo', tag: 'Clash.Meta с богатыми группами', chips: ['fallback и load-balance', 'Clash-дашборды', 'fake-ip', 'правила .mrs'], pkg: true },
  amnezia: { name: 'amnezia-box', tag: 'sing-box с AmneziaWG: обход блокировок WireGuard', chips: ['всё из sing-box', 'AmneziaWG', 'сжатая сборка'], pkg: false },
};
const ORDER = ['singbox', 'mihomo', 'amnezia'];

export default async function (root) {
  const s = S.settings;
  let alive = true, pollT = 0;
  const meterBox = h('div');
  const coreRows = h('div');
  const podkopBox = h('div');
  const depBox = h('div');
  let depT = 0;
  const jobBox = h('div');
  apd(root, pageHead('Компоненты', 'Ядра sing-box, Mihomo и amnezia-box, а также Podkop: установка, удаление и выбор активного ядра'),
    h('div', { class: 'bay' }, meterBox, coreRows, podkopBox, depBox), jobBox);

  // Хватает ли места под установку: свободное место + размер уже стоящей копии (она заменится).
  function space(id) {
    const sg = (S.system && S.system.storage) || {};
    const free = sg.free_mb, need = (sg.need_mb || {})[id] || 0;
    if (free == null || !need) return { ok: true };
    const have = free + ((sg.installed_mb || {})[id] || 0);
    return { ok: free <= 0 || have >= need, free, need, dir: sg.dir };
  }

  function drawMeter() {
    const sg = (S.system && S.system.storage) || {};
    const need = sg.need_mb || {};
    const free = sg.free_mb == null ? 0 : sg.free_mb;
    const marks = ORDER.map((id) => [CORES[id].name, need[id] || 0]).concat([['Podkop', pk.need || 20]]).filter((m) => m[1] > 0);
    const scale = Math.max(...marks.map((m) => m[1])) * 1.25; // шкала по самому большому компоненту; больше свободного места — заполнено целиком
    const fill = h('i'); fill.style.width = Math.min(100, free / scale * 100) + '%';
    const track = h('div', { class: 'meter-track', role: 'img', 'aria-label': 'Свободно ' + free + ' МБ' }, fill);
    const labels = h('div', { class: 'meter-marks' });
    for (const [n, v] of marks.slice().sort((x, y) => x[1] - y[1])) {
      const t = h('b', { class: 'tick ' + (free >= v ? 'fit' : 'nofit'), title: n + ': около ' + v + ' МБ' }); t.style.left = Math.min(98, v / scale * 100) + '%';
      track.append(t);
      labels.append(h('span', { class: free >= v ? 'fit' : 'nofit' }, n + ' — ' + v + ' МБ'));
    }
    clear(meterBox).append(h('div', { class: 'meter' },
      h('div', { class: 'meter-head' }, h('b', 'Свободно ' + (sg.free_mb == null ? '—' : free + ' МБ')),
        h('span', { class: 'mute small' }, 'Ядра ставятся в ', h('code', sg.dir || '—'), ' — каталог меняется ниже')),
      track, labels));
  }

  function draw() {
    const cores = (S.system && S.system.cores) || {};
    drawMeter();
    clear(coreRows);
    for (const id of ORDER) {
      const c = CORES[id], info = cores[id] || {};
      const sel = s.core === id;
      const sp = space(id);
      const lack = !sp.ok;
      const btn = h('button', { class: 'btn primary' + (lack ? ' lowspace' : ''), disabled: lack, title: lack ? 'Не хватает места' : null, onclick: (e) => { e.stopPropagation(); install(id, ''); } }, info.installed ? 'Обновить' : 'Установить');
      const pkgBtn = c.pkg ? h('button', { class: 'btn', title: 'Пакет из репозитория OpenWrt/Entware (opkg или apk): обычно компактнее релиза GitHub.', onclick: (e) => { e.stopPropagation(); install(id, '', 'package'); } }, 'Из пакетов системы') : null;
      const delBtn = h('button', { class: 'btn danger', onclick: async (e) => { e.stopPropagation(); remove(id); } }, 'Удалить');
      const pick = h('input', { type: 'radio', name: 'core', checked: sel, 'aria-label': 'Использовать ' + c.name, onchange: () => { s.core = id; st.touch(); draw(); } });
      coreRows.append(h('div', { class: 'mod' + (sel ? ' on' : ''), onclick: (e) => { if (e.target.closest('button,input,label,details')) return; pick.click(); } },
        h('div', { class: 'mod-head' }, h('label', { class: 'mod-name' }, pick, h('b', c.name)),
          h('span', { class: 'mod-tag' }, c.tag), h('span', { class: 'grow' }),
          sel ? badge('активно', 'acc') : null, info.installed ? badge('установлено', 'ok') : badge('не установлено', 'warn')),
        h('div', { class: 'chips' }, c.chips.map((x) => h('span', x))),
        h('div', { class: 'mod-meta mono small' }, info.installed ? [h('span', 'v' + (info.version || '?').replace(/^v/, '')), h('span', info.path)] : [h('span', 'нужно около ' + (sp.need || '?') + ' МБ')]),
        lack ? note('warn', 'Не хватает места в ' + (sp.dir || 'каталоге установки') + ': свободно ' + sp.free + ' МБ, нужно около ' + sp.need + ' МБ. Скачанный файл при нехватке места удаляется. Подключите накопитель и укажите каталог установки ниже' + (c.pkg ? ' либо поставьте ядро «Из пакетов системы».' : '.')) : null,
        h('div', { class: 'mod-act' }, btn, pkgBtn, info.installed ? delBtn : null)));
    }
  }

  async function remove(core) {
    if (!(await confirmBox('Удалить ' + CORES[core].name + ' с роутера? Освободится место на флеш-памяти; настройки панели сохранятся.', 'Удалить', true))) return;
    try {
      const r = await post('api/core/remove', { core });
      toast('Удалено: ' + r.removed, 'ok');
      await st.loadSystem(); draw();
    } catch (e) { toastErr(e); }
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
    jobBox.append(h('div', { class: 'card' }, h('h2', 'Установка ' + st.coreName(j.core)),
      j.error ? note('err', j.error) : null,
      h('div', { class: 'row small', style: 'margin-bottom:6px' }, j.running ? h('span', { class: 'spin' }) : null, h('span', j.message || j.stage || ''), h('span', { class: 'grow' }), h('span', (j.percent || 0) + '%')),
      h('div', { class: 'progress', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(j.percent || 0) }, bar)));
  }

  // ---------- Podkop ----------
  let pkT = 0;
  const pk = { need: 20 };
  async function pkAct(name, confirmText) {
    if (confirmText && !(await confirmBox(confirmText, 'Продолжить', name === 'remove'))) return;
    try { await post('api/podkop/' + name); toast('Готово', 'ok'); } catch (e) { toastErr(e); }
    pkLoad();
  }
  async function pkLoad() {
    clearTimeout(pkT);
    let p;
    try { p = await get('api/podkop'); } catch (e) { if (alive) clear(podkopBox).append(h('div', { class: 'mod' }, h('b', 'Podkop'), note('err', e.message))); return; }
    if (!alive) return;
    pk.need = p.need_mb || 20; if (alive) drawMeter();
    const busy = p.job && p.job.running;
    const force = !!(s.download && s.download.force_install);
    const lack = p.supported && !p.installed && p.free_mb > 0 && p.free_mb < p.need_mb;
    const blocked = lack && !force;
    const kids = [h('div', { class: 'mod-head' }, h('span', { class: 'mod-name' }, h('b', 'Podkop')),
      h('span', { class: 'mod-tag' }, 'Маршрутизация по спискам на базе sing-box для OpenWrt'), h('span', { class: 'grow' }),
      p.installed ? (p.running ? badge('работает', 'ok') : badge('остановлен')) : null,
      p.installed ? badge('установлено', 'ok') : badge('не установлено', 'warn'))];
    if (!p.supported) kids.push(h('p', { class: 'small mute' }, p.reason));
    else {
      kids.push(h('div', { class: 'chips' }, ['OpenWrt 24.10+', 'свои списки доменов', 'управляет sing-box и dnsmasq', 'не работает вместе с ядром панели'].map((x) => h('span', x))));
      kids.push(h('div', { class: 'mod-meta mono small' }, p.installed
        ? [h('span', 'v' + (p.version || '?').replace(/^v/, '')), h('span', 'свободно ' + p.free_mb + ' МБ')]
        : [h('span', 'нужно от ' + p.need_mb + ' МБ, свободно ' + p.free_mb + ' МБ')]));
      if (lack) kids.push(note('warn', force
        ? 'Места меньше рекомендованного (' + p.free_mb + ' из ' + p.need_mb + ' МБ), но включена принудительная установка: при неудаче всё установленное будет удалено.'
        : 'Не хватает места: свободно ' + p.free_mb + ' МБ, нужно не меньше ' + p.need_mb + ' МБ (на устройствах с флеш-памятью 16 МБ Podkop не поддерживается). Освободите место, подключите extroot или включите «Принудительная установка» в настройках ниже и сохраните их.'));
      kids.push(p.installed
        ? h('div', { class: 'mod-act' },
          h('button', { class: 'btn primary', disabled: busy, onclick: () => pkAct('start') }, 'Запустить'),
          h('button', { class: 'btn', disabled: busy, onclick: () => pkAct('restart') }, 'Перезапустить'),
          h('button', { class: 'btn', disabled: busy, onclick: () => pkAct('stop') }, 'Остановить'),
          h('button', { class: 'btn', disabled: busy, onclick: () => pkAct('enable') }, 'В автозапуск'),
          h('button', { class: 'btn', disabled: busy, onclick: () => pkAct('disable') }, 'Убрать из автозапуска'),
          h('button', { class: 'btn danger', disabled: busy, onclick: () => pkAct('remove', 'Остановить и удалить Podkop (пакеты podkop, luci-app-podkop, luci-i18n-podkop-ru)?') }, 'Удалить'))
        : h('div', { class: 'mod-act' + (blocked ? ' lowspace' : '') },
          h('button', { class: 'btn primary', disabled: busy || blocked, onclick: () => pkAct('install', 'Скачать последний релиз Podkop с GitHub (itdoginfo/podkop) и установить пакет podkop? Зависимости (sing-box и др.) подтянутся из репозиториев роутера.' + (force ? ' Включена принудительная установка: при неудаче всё установленное будет удалено.' : '')) }, force && lack ? 'Установить принудительно' : 'Установить')));
      if (p.job && (p.job.running || p.job.finished)) {
        const pre = h('pre', { class: 'mono', style: 'max-height:300px;overflow:auto;white-space:pre-wrap;margin-top:10px' }, (p.job.output || []).join('\n'));
        kids.push(h('div', { class: 'small', style: 'margin-top:10px' }, h('b', p.job.title || 'Операция')),
          p.job.error ? note('err', p.job.error) : (p.job.finished ? note('ok', 'Завершено') : h('p', { class: 'mute' }, h('span', { class: 'spin' }), 'Выполняется…')), pre);
        setTimeout(() => { pre.scrollTop = pre.scrollHeight; }, 0);
      }
    }
    clear(podkopBox).append(h('div', { class: 'mod' }, kids));
    if (busy && alive) pkT = setTimeout(pkLoad, 1500);
  }

  async function depLoad() {
    clearTimeout(depT);
    let k;
    try { k = await get('api/kmods'); } catch (e) { return; }
    if (!alive) return;
    clear(depBox);
    if (!k.installable) return;
    const j = k.job || {};
    const have = k.present || [];
    const why = { 'kmod-tun': 'устройство TUN', 'kmod-nft-tproxy': 'режим tproxy', 'kmod-nft-queue': 'auto_redirect в TUN' };
    depBox.append(h('div', { class: 'mod' },
      h('div', { class: 'mod-head' }, h('b', { class: 'mod-name' }, 'Зависимые компоненты'), h('span', { class: 'mod-tag' }, 'Модули ядра для TUN и tproxy'), h('span', { class: 'grow' }),
        have.length ? badge('установлено: ' + have.length, 'ok') : badge('нет', 'warn')),
      h('div', { class: 'chips' }, have.length ? have.map((p) => h('span', p + ' — ' + (why[p] || ''))) : [h('span', 'ничего не установлено')]),
      h('div', { class: 'row', style: 'flex-wrap:wrap;gap:8px;margin-top:10px' },
        h('button', { class: 'btn danger', disabled: !have.length || !!j.running, onclick: async () => {
          if (!(await confirmBox('Удалить ' + have.join(', ') + '? Режимы TUN и tproxy перестанут работать, пока пакеты не будут установлены снова (страница «Входящие, TUN, сеть»). Удалятся только эти пакеты, ядра и Podkop не затрагиваются.', 'Удалить', true))) return;
          try { await post('api/kmods/remove'); toast('Удаляю…', 'ok'); } catch (e) { toastErr(e); }
          depLoad();
        } }, j.running ? 'Выполняется…' : 'Удалить зависимые компоненты')),
      j.error ? note('err', j.error) : null,
      (j.running || j.finished) && j.title === 'Удаление зависимых компонентов' ? h('pre', { class: 'mono', style: 'max-height:220px;overflow:auto;white-space:pre-wrap;margin-top:10px' }, (j.output || []).join('\n')) : null));
    if (j.running && alive) depT = setTimeout(depLoad, 1500);
  }

  draw();
  pkLoad();
  depLoad();
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
        field('Свой бинарник Mihomo', txt(d, 'mihomo_path', { ph: '/opt/bin/mihomo' })),
        field('Свой бинарник amnezia-box', txt(d, 'amnezia_path', { ph: '/opt/bin/amnezia-box' }))),
      chk(d, 'force_install', 'Принудительная установка Podkop', 'Ставить Podkop, даже если свободного места меньше 25 МБ. Если установка не удалась, всё скачанное и установленное в этой попытке удаляется. Вступает в силу после сохранения настроек.', { onchange: () => pkLoad() }),
      h('div', { class: 'row' }, h('p', { class: 'small mute grow' }, 'Изменения вступают в силу после сохранения настроек. Свободное место считается по сохранённому каталогу.'),
        h('button', { class: 'btn', onclick: async () => { try { await st.loadSystem(); draw(); pkLoad(); toast('Место пересчитано', 'ok'); } catch (e) { toastErr(e); } } }, 'Пересчитать место'))));
  return () => { alive = false; clearTimeout(pollT); clearTimeout(pkT); clearTimeout(depT); };
}
