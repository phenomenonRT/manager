import { errNote, apd, h, clear, pageHead, badge, note, fmtBytes, fmtDur, toast, toastErr, spinner } from '../ui.js';
import { get, post, put, streamJSON } from '../api.js';
import * as st from '../state.js';
import { transparentNote } from '../transparent.js';
import { loadAwgStates, awgBadge, delayClass } from '../awgstatus.js';

const S = st.S;
const STATE_RU = { running: 'работает', stopped: 'остановлен', starting: 'запускается', stopping: 'останавливается', error: 'ошибка', failed: 'ошибка', waiting: 'ждёт сеть' };
const TEST_URL = 'https://www.gstatic.com/generate_204';

export default async function (root) {
  const timers = []; const ctl = new AbortController(); let alive = true;
  const stop = () => { alive = false; timers.forEach(clearInterval); ctl.abort(); };

  const svcBox = h('div', { class: 'card' });
  const pendBox = h('div');
  const platBox = h('div', { class: 'card' });
  const clashBox = h('div');
  apd(root, pageHead('Обзор', 'Состояние сервиса, трафик и подключения'), pendBox,
    h('div', { class: 'cols' }, svcBox, platBox), h('div', { style: 'height:14px' }), clashBox);

  // ---- сервис ----
  async function act(kind, btn) {
    btn.disabled = true;
    try { await post('api/service/' + kind); toast({ start: 'Запущено', stop: 'Остановлено', restart: 'Перезапущено' }[kind], 'ok'); }
    catch (e) { toastErr(e); }
    await refresh();
  }
  function drawSvc() {
    const s = S.status;
    if (!s) { clear(svcBox).append(h('h2', 'Сервис'), note('err', 'Нет данных о состоянии')); return; }
    const run = s.state === 'running' || s.state === 'starting' || s.state === 'waiting';
    const mk = (kind, text, cls) => { const b = h('button', { class: 'btn ' + (cls || ''), onclick: () => act(kind, b) }, text); return b; };
    const kind = s.state === 'running' ? 'ok' : s.state === 'error' || s.state === 'failed' ? 'err' : 'warn';
    clear(svcBox).append(h('h2', 'Сервис'),
      h('div', { class: 'row', style: 'margin-bottom:10px' }, badge(STATE_RU[s.state] || s.state, kind),
        s.core ? badge(st.coreName(s.core), 'acc') : null),
      h('dl', { class: 'kv', style: 'margin-bottom:10px' },
        h('dt', 'PID'), h('dd', s.pid ? String(s.pid) : '—'),
        h('dt', 'Аптайм'), h('dd', run && s.uptime_sec ? fmtDur(s.uptime_sec) : '—'),
        h('dt', 'Версия'), h('dd', s.version || '—'),
        h('dt', 'Перезапусков'), h('dd', String(s.restarts || 0))),
      s.notice ? note('', s.notice) : null,
      s.error ? errNote(h('b', 'Ошибка ядра: '), s.error) : null,
      s.firewall_error ? errNote(h('b', 'Ошибка брандмауэра: '), s.firewall_error) : null,
      (s.warnings && s.warnings.length) ? note('warn', h('b', 'Предупреждения генератора:'), h('ul', s.warnings.map((w) => h('li', w)))) : null,
      h('div', { class: 'row' }, run ? mk('restart', 'Перезапустить', 'primary') : mk('start', 'Запустить', 'primary'), run ? mk('stop', 'Остановить') : null));
  }
  function drawPend() {
    clear(pendBox);
    const tn = transparentNote(); if (tn) pendBox.append(tn);
    if (st.isDirty()) pendBox.append(note('warn', h('b', 'Есть несохранённые изменения. '), 'Сохраните их кнопкой внизу страницы.'));
    else if (S.needApply) pendBox.append(note('warn', h('b', 'Настройки сохранены, но не применены. '), 'Нажмите «Применить» внизу или перезапустите сервис.'));
  }
  function drawPlat() {
    const p = (S.system && S.system.platform) || {};
    clear(platBox).append(h('h2', 'Платформа'), h('dl', { class: 'kv' },
      h('dt', 'Система'), h('dd', p.os_name || p.os || '—'),
      h('dt', 'Архитектура'), h('dd', (p.arch || '—') + (p.machine ? ' (' + p.machine + ')' : '')),
      h('dt', 'Память'), h('dd', p.mem_total_mb ? p.mem_total_mb + ' МБ' : '—'),
      h('dt', 'Свободно в ' + (p.bin_dir || 'каталоге ядер')), h('dd', p.bin_free_mb != null ? h('span', { class: p.bin_free_mb < 70 ? 'lowspace' : '', title: p.bin_free_mb < 70 ? 'Мало места: ядру нужно 30–40 МБ. Каталог установки меняется в «Компоненты».' : '' }, p.bin_free_mb + ' МБ') : '—'),
      h('dt', 'LAN-интерфейс'), h('dd', p.lan_iface || '—'),
      h('dt', 'Брандмауэр'), h('dd', p.firewall_backend || '—'),
      h('dt', 'Панель'), h('dd', (S.system && S.system.panel_version) || '—')),
    (p.notes && p.notes.length) ? h('div', { style: 'margin-top:10px' }, p.notes.map((n) => note('', n))) : null);
  }

  // ---- Clash: трафик, прокси, подключения ----
  const hist = { up: [], down: [] };
  let clashOn = null, trafficStarted = false;
  const ui = {};
  function buildClash() {
    ui.up = h('div', { class: 'big' }, '—'); ui.down = h('div', { class: 'big' }, '—');
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('class', 'spark'); svg.setAttribute('viewBox', '0 0 120 40'); svg.setAttribute('preserveAspectRatio', 'none'); svg.setAttribute('aria-hidden', 'true');
    ui.spUp = document.createElementNS(NS, 'polyline'); ui.spUp.setAttribute('stroke', 'var(--warn)');
    ui.spDown = document.createElementNS(NS, 'polyline'); ui.spDown.setAttribute('stroke', 'var(--accent)');
    svg.append(ui.spUp, ui.spDown);
    ui.tot = h('div', { class: 'small mute' });
    ui.proxies = h('div', { class: 'card' }, h('h2', 'Выбор узла'), spinner());
    ui.conns = h('div');
    clear(clashBox).append(
      h('div', { class: 'card' }, h('h2', 'Трафик'),
        h('div', { class: 'row', style: 'gap:28px' }, h('div', h('div', { class: 'small mute' }, '↑ отдача'), ui.up), h('div', h('div', { class: 'small mute' }, '↓ загрузка'), ui.down)),
        svg, ui.tot),
      ui.proxies, ui.conns);
  }
  function drawSpark() {
    const max = Math.max(1024, ...hist.up, ...hist.down);
    const pts = (a) => a.map((v, i) => (i * 2) + ',' + (38 - v / max * 36).toFixed(1)).join(' ');
    ui.spUp.setAttribute('points', pts(hist.up)); ui.spDown.setAttribute('points', pts(hist.down));
  }
  async function startTraffic() {
    if (trafficStarted) return; trafficStarted = true;
    try {
      await streamJSON('api/clash/traffic', (o) => {
        if (!alive || !ui.up) return;
        hist.up.push(o.up || 0); hist.down.push(o.down || 0);
        if (hist.up.length > 60) { hist.up.shift(); hist.down.shift(); }
        ui.up.textContent = fmtBytes(o.up) + '/с'; ui.down.textContent = fmtBytes(o.down) + '/с';
        drawSpark();
      }, ctl.signal);
    } catch (e) { /* ядро остановлено — ничего страшного */ }
    trafficStarted = false;
  }
  async function loadProxies() {
    try {
      const r = await get('api/clash/proxies', { signal: ctl.signal });
      drawProxies((r && r.proxies) || {});
    } catch (e) { if (alive) clear(ui.proxies).append(h('h2', 'Выбор узла'), note('warn', 'Не удалось получить список прокси: ' + e.message)); }
  }
  const delays = {}, busy = {};
  // Состояние туннелей AmneziaWG: ядро отдаёт его только в журнале, и только на уровне debug.
  // Показываем точкой у узла в списке: зелёная — рукопожатие есть, красная — нет.
  let awgState = {}, lastAll = null;
  async function loadAwg() {
    if (!((S.settings && S.settings.nodes) || []).some((n) => n.type === 'awg' && !n.disabled)) return;
    try { awgState = await loadAwgStates(get, ctl.signal); } catch (e) { return; }
    if (alive && ui.proxies && lastAll) drawProxies(lastAll);
  }
  function drawProxies(all) {
    lastAll = all;
    const groups = Object.entries(all).filter(([n, p]) => n !== 'GLOBAL' && Array.isArray(p.all));
    clear(ui.proxies).append(h('h2', 'Выбор узла'));
    if (!groups.length) { ui.proxies.append(h('div', { class: 'empty' }, 'Групп пока нет. Создайте их в разделе «Группы».')); return; }
    if (diag) ui.proxies.append(note('warn', h('div', h('b', diagTitle || 'Что пишет ядро (последние ошибки):'), h('pre', { class: 'mono small', style: 'white-space:pre-wrap;word-break:break-word;margin:6px 0 0;max-height:200px;overflow:auto' }, diag.join('\n')))));
    for (const [name, g] of groups) {
      const isSel = /^selector$/i.test(g.type);
      const chips = g.all.map((m) => {
        const d = delays[m] !== undefined ? delays[m] : (all[m] && all[m].history && all[m].history.length ? all[m].history[all[m].history.length - 1].delay : undefined);
        const lab = busy[m] ? '…' : d === undefined ? '' : d > 0 ? d + ' мс' : 'сбой';
        const isAwg = ((S.settings && S.settings.nodes) || []).some((n) => n.name === m && n.type === 'awg');
        const hs = isAwg ? awgBadge(awgState[m], (S.settings.general || {}).log_level === 'debug') : null;
        // Клик по узлу проверяет его задержку; в ручной группе он ещё и выбирается.
        return h('button', {
          type: 'button', class: 'chip' + (g.now === m ? ' on' : '') + (' ' + delayClass(d)), disabled: !!busy[m],
          'aria-pressed': g.now === m ? 'true' : 'false',
          title: (hs ? 'AmneziaWG: ' + hs.text + '. ' + hs.tip + ' ' : '') + (delayErr[m] ? 'Ошибка проверки: ' + delayErr[m] + '. ' : '') + (m === 'block' ? 'Блокировка не отвечает по определению' : isSel ? 'Выбрать и проверить задержку' : 'Проверить задержку'),
          onclick: async () => {
            if (isSel) { try { await put('api/clash/proxies/' + encodeURIComponent(name), { name: m }); g.now = m; } catch (e) { toastErr(e); return; } }
            if (m === 'block') { drawProxies(all); return; }
            busy[m] = true; drawProxies(all);
            const cfg = (S.settings.groups || []).find((x) => x.name === name);
            await testDelay(m, (cfg && cfg.url) || TEST_URL, cfg && cfg.timeout);
            busy[m] = false;
            if (!alive) return;
            if (delayErr[m]) { await loadDiag([m]); loadAwg(); }
            drawProxies(all);
          },
        }, hs ? h('i', { class: 'hs ' + (hs.kind || 'none'), 'aria-hidden': 'true' }) : null, m, h('small', lab));
      });
      const testAll = h('button', { class: 'btn sm', onclick: async () => {
        testAll.disabled = true; testAll.textContent = 'Проверка…';
        const queue = g.all.filter((m) => m !== 'block'); // block не отвечает по определению
        const cfg = (S.settings.groups || []).find((x) => x.name === name);
        const url = (cfg && cfg.url) || TEST_URL;
        const worker = async () => { while (queue.length && alive) { const m = queue.shift(); await testDelay(m, url, cfg && cfg.timeout); } };
        await Promise.all([worker(), worker(), worker(), worker()]);
        if (!alive) return;
        drawProxies(all);
        const bad = g.all.filter((m) => delayErr[m]);
        const total = g.all.filter((m) => m !== 'block').length;
        if (bad.length && bad.length === total) {
          const errMsg = delayErr[bad[0]];
          await loadDiag(bad); drawProxies(all);
          const dnsFail = (diag || []).some((x) => /lookup failed|dns:.*(timeout|deadline)/i.test(x));
          const hsFail = (diag || []).some((x) => /handshake did not complete/i.test(x)) && !(diag || []).some((x) => /received handshake response/i.test(x));
          toast(hsFail
            ? 'Туннель AWG не поднялся: ядро отправляет рукопожатие, но сервер не отвечает. Это не DNS и не адрес проверки. Сверьте с сервером ключи (PrivateKey, PublicKey, PresharedKey), Jc/Jmin/Jmax, S1–S4, H1–H4 и I1–I5 — они должны совпадать до символа. Проверьте, что UDP-порт сервера доступен с роутера (провайдер часто режет нестандартные UDP) и что конфиг работает в официальном клиенте AmneziaWG.'
            : dnsFail
            ? 'Узлы не проверены: ядро не смогло определить адрес ' + hostOf(url) + ' (DNS не ответил за отведённое время). Это не обязательно сбой VPN. Выберите проверку «по IP» в «Группы → Параметры проверки» и посмотрите «DNS»: если трафик DNS идёт напрямую (Final = direct), DoH/DoT часто режутся провайдером. Задайте «Remote через» — группу.'
            : 'Ни один узел не ответил на ' + url + ' за ' + Math.round(((cfg && cfg.timeout) || 10000) / 1000) + ' с (' + errMsg + '). Проверьте адрес, ключи и параметры AWG узла, интерфейс WAN и «Интерфейс по умолчанию» (при TUN). Подробности — в блоке ниже и в «Логи».', 'err');
        }
      } }, 'Проверить задержку');
      ui.proxies.append(h('div', { style: 'margin-bottom:12px' },
        h('div', { class: 'row', style: 'margin-bottom:6px' }, h('b', name), badge(g.type), h('span', { class: 'small mute' }, 'сейчас: ' + (g.now || '—')), h('span', { class: 'grow' }), testAll),
        h('div', { class: 'chips' }, chips)));
    }
  }
  const hostOf = (u) => { try { return new URL(u).hostname; } catch (e) { return u; } };
  const delayErr = {};
  let diagTitle = '';
  let diag = null; // выдержка из журнала ядра после неудачной проверки: показывает настоящую причину
  // names — узлы, проверка которых не прошла: подсказка зависит от их типа (AWG, системный VPN-интерфейс и т. д.)
  async function loadDiag(names) {
    try {
      const r = await get('api/logs?n=60');
      const ls = ((r && r.lines) || []).map((x) => (typeof x === 'string' ? x : x.text || x.line || JSON.stringify(x)));
      const hit = ls.filter((x) => /\b(ERROR|WARN|FATAL|PANIC)\b/.test(x) || /handshake|timeout|refused|unreachable|lookup failed|no route|no such device/i.test(x)).slice(-8);
      const nodes = (S.settings.nodes || []).filter((n) => (names || []).includes(n.name));
      diagTitle = hit.length ? 'Что пишет ядро (последние ошибки):' : 'Подсказка:';
      if (hit.length) { diag = hit; return; }
      const hints = ['В журнале ядра нет ошибок — значит, ядро запрос отправило, а ответа не получило.'];
      const ifn = nodes.filter((n) => n.type === 'iface' && n.bind_interface);
      if (ifn.length) {
        let list = [], checks = null;
        try { list = (await get('api/interfaces')) || []; } catch (e) { /* список необязателен */ }
        try { checks = await get('api/iface-check'); } catch (e) { /* панель могла быть старой версии */ }
        for (const n of ifn) {
          const iface = n.bind_interface;
          const i = list.find((x) => x.name === iface);
          const c = (checks || []).find((x) => x.node === n.name);
          if (c && !c.rule) {
            hints.push('Панель не поставила правило выхода через «' + iface + '»: правила «oif» (приоритет ' + c.pref + ') нет в системе, поэтому трафик узла никуда не уходит. Правило ставится при запуске ядра и обновляется каждые 15 с — перезапустите ядро (Сервис → Перезапустить) и повторите проверку. Если оно так и не появилось, проверьте на роутере: ip rule show | grep ' + c.pref + (c.out ? '\n' + c.out : ''));
          } else if (c && !c.route) {
            hints.push('Правило «oif» для «' + iface + '» есть, а в таблице ' + c.table + ' нет маршрута по умолчанию через интерфейс. Маршрут ставится при запуске ядра — перезапустите его. Если не помогло, проверьте: ip route show table ' + c.table + (c.out ? '\n' + c.out : ''));
          } else if (c) {
            hints.push('Правило (приоритет ' + c.pref + ') и маршрут (таблица ' + c.table + ') для «' + iface + '» на месте: панель уводит трафик в интерфейс, но ответа нет — это уже проблема самого туннеля, а не панели. Посмотрите пакеты во время проверки: tcpdump -l -ni ' + iface + ' (SYN уходит, а SYN-ACK не приходит). Туннель может «умереть», оставаясь поднятым, — перезапустите usque на роутере и повторите. Таймаут проверки — 10–15 с в «Группы → Параметры проверки».');
          } else if (!i) {
            hints.push('Интерфейс «' + iface + '» (узел «' + n.name + '») не найден в системе: VPN не запущен или интерфейс называется иначе.');
          } else if (!i.up) {
            hints.push('Интерфейс «' + iface + '» (узел «' + n.name + '») не активен: запустите VPN на роутере.');
          } else {
            hints.push('Интерфейс «' + iface + '» поднят' + ((i.addrs || []).length ? ' (' + i.addrs[0] + ')' : ' без IP-адреса') + ', но через него нет ответа и сведений о правиле нет (панель старой версии). Сначала повторите проверку: туннели вроде WARP часто теряют первый пакет после простоя, поэтому в «Группы → Параметры проверки» поставьте таймаут 10–15 с. Если не помогает, посмотрите пакеты во время проверки: tcpdump -l -ni ' + iface + ' (SYN уходит, а SYN-ACK не приходит — проблема в самом туннеле).');
          }
        }
      } else if (nodes.some((n) => n.type === 'awg')) {
        hints.push('Уровень логов «warn» не показывает рукопожатие AWG: поставьте info в «Входящие, TUN, сеть → Общие», перезапустите ядро и повторите проверку.');
      }
      diag = hints;
    } catch (e) { diag = null; }
  }
  async function testDelay(name, url, timeout) {
    const ms = Math.min(60000, Math.max(1000, Number(timeout) || 10000));
    // Туннели вроде WARP теряют первый пакет после простоя: первая удачная проверка может включать
    // около секунды на повторную отправку пакета. Для узла-интерфейса делаем до трёх попыток и берём
    // лучший результат: холодный туннель успевает «разогреться», а цифра отражает реальную задержку.
    const isIface = ((S.settings && S.settings.nodes) || []).some((n) => n.name === name && n.type === 'iface');
    const max = isIface ? 3 : 1;
    let best = 0, lastErr = '';
    for (let attempt = 0; attempt < max; attempt++) {
      try {
        const r = await get('api/clash/proxies/' + encodeURIComponent(name) + '/delay?url=' + encodeURIComponent(url || TEST_URL) + '&timeout=' + ms, { signal: ctl.signal });
        const d = (r && r.delay) || 0;
        if (d > 0 && (best === 0 || d < best)) best = d;
        if (!isIface || (best > 0 && best < 900)) break; // меньше секунды — туннель уже разогрет, хватит
      } catch (e) {
        if (!alive) return;
        lastErr = (e && e.message) || 'ошибка';
      }
    }
    if (best > 0) { delays[name] = best; delete delayErr[name]; return; }
    delays[name] = 0;
    if (lastErr) delayErr[name] = lastErr; else delete delayErr[name];
  }
  async function loadConns() {
    try {
      const r = await get('api/clash/connections', { signal: ctl.signal });
      if (!alive) return;
      const list = (r.connections || []).slice().sort((a, b) => (b.download + b.upload) - (a.download + a.upload)).slice(0, 80);
      ui.tot.textContent = 'Всего: ↑ ' + fmtBytes(r.uploadTotal) + ', ↓ ' + fmtBytes(r.downloadTotal) + ' · подключений: ' + (r.connections || []).length;
      clear(ui.conns).append(h('div', { class: 'card' }, h('h2', 'Подключения' + (list.length ? ' (топ ' + list.length + ' по объёму)' : '')),
        list.length ? h('div', { class: 'tw' }, h('table', h('thead', h('tr', ['Назначение', 'Сеть', 'Цепочка', 'Правило', '↑', '↓', 'Источник'].map((x) => h('th', x)))),
          h('tbody', list.map((c) => {
            const m = c.metadata || {};
            return h('tr', h('td', { class: 'mono' }, (m.host || m.destinationIP || '?') + ':' + (m.destinationPort || '')), h('td', m.network || ''),
              h('td', (c.chains || []).slice().reverse().join(' → ')), h('td', c.rule || ''), h('td', { class: 'nowrap' }, fmtBytes(c.upload)),
              h('td', { class: 'nowrap' }, fmtBytes(c.download)), h('td', { class: 'mono' }, m.sourceIP || ''));
          })))) : h('div', { class: 'empty' }, 'Активных подключений нет')));
    } catch (e) { /* ядро могло остановиться — следующая итерация разберётся */ }
  }
  function drawOff() {
    const r = S.status && (S.status.state === 'error' || S.status.state === 'failed');
    clear(clashBox).append(note('', 'Ядро не запущено — график трафика, выбор узла и список подключений появятся после запуска.' + (r ? ' Подробности ошибки — в карточке «Сервис» и в разделе «Логи».' : '')));
    clashOn = false; ui.up = null;
  }
  function syncClash() {
    const run = S.status && S.status.state === 'running';
    if (run && clashOn !== true) { clashOn = true; buildClash(); loadProxies(); loadAwg(); startTraffic(); loadConns(); }
    else if (!run && clashOn !== false) drawOff();
  }

  async function refresh() { try { await st.loadStatus(); } catch (e) { /* покажем старое */ } paint(); }
  function paint() { if (!alive) return; drawSvc(); drawPend(); drawPlat(); syncClash(); }
  const unsub = st.subscribe(() => { if (alive) { drawPend(); } });
  let tick = 0;
  paint();
  timers.push(setInterval(() => { if (!document.hidden) { refresh(); if (clashOn) { tick++; if (tick % 2 === 0) loadConns(); startTraffic(); if (tick % 4 === 0) loadAwg(); if (tick % 8 === 0) loadProxies(); } } }, 2500));
  return () => { stop(); unsub(); };
}
