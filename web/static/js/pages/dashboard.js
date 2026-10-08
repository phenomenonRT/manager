import { apd, h, clear, pageHead, badge, note, fmtBytes, fmtDur, toast, toastErr, spinner } from '../ui.js';
import { get, post, put, streamJSON } from '../api.js';
import * as st from '../state.js';

const S = st.S;
const STATE_RU = { running: 'работает', stopped: 'остановлен', starting: 'запускается', stopping: 'останавливается', error: 'ошибка', failed: 'ошибка' };
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
    const run = s.state === 'running' || s.state === 'starting';
    const mk = (kind, text, cls) => { const b = h('button', { class: 'btn ' + (cls || ''), onclick: () => act(kind, b) }, text); return b; };
    const kind = s.state === 'running' ? 'ok' : s.state === 'error' || s.state === 'failed' ? 'err' : 'warn';
    clear(svcBox).append(h('h2', 'Сервис'),
      h('div', { class: 'row', style: 'margin-bottom:10px' }, badge(STATE_RU[s.state] || s.state, kind),
        s.core ? badge(s.core === 'mihomo' ? 'Mihomo' : 'sing-box', 'acc') : null),
      h('dl', { class: 'kv', style: 'margin-bottom:10px' },
        h('dt', 'PID'), h('dd', s.pid ? String(s.pid) : '—'),
        h('dt', 'Аптайм'), h('dd', run && s.uptime_sec ? fmtDur(s.uptime_sec) : '—'),
        h('dt', 'Версия'), h('dd', s.version || '—'),
        h('dt', 'Перезапусков'), h('dd', String(s.restarts || 0))),
      s.error ? note('err', h('b', 'Ошибка ядра: '), s.error) : null,
      s.firewall_error ? note('err', h('b', 'Ошибка брандмауэра: '), s.firewall_error) : null,
      (s.warnings && s.warnings.length) ? note('warn', h('b', 'Предупреждения генератора:'), h('ul', s.warnings.map((w) => h('li', w)))) : null,
      h('div', { class: 'row' }, run ? mk('restart', 'Перезапустить', 'primary') : mk('start', 'Запустить', 'primary'), run ? mk('stop', 'Остановить') : null));
  }
  function drawPend() {
    clear(pendBox);
    if (st.isDirty()) pendBox.append(note('warn', h('b', 'Есть несохранённые изменения. '), 'Сохраните их кнопкой внизу страницы.'));
    else if (S.needApply) pendBox.append(note('warn', h('b', 'Настройки сохранены, но не применены. '), 'Нажмите «Применить» внизу или перезапустите сервис.'));
  }
  function drawPlat() {
    const p = (S.system && S.system.platform) || {};
    clear(platBox).append(h('h2', 'Платформа'), h('dl', { class: 'kv' },
      h('dt', 'Система'), h('dd', p.os_name || p.os || '—'),
      h('dt', 'Архитектура'), h('dd', (p.arch || '—') + (p.machine ? ' (' + p.machine + ')' : '')),
      h('dt', 'Память'), h('dd', p.mem_total_mb ? p.mem_total_mb + ' МБ' : '—'),
      h('dt', 'Свободно в ' + (p.bin_dir || 'каталоге ядер')), h('dd', p.bin_free_mb != null ? p.bin_free_mb + ' МБ' : '—'),
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
  const delays = {};
  function drawProxies(all) {
    const groups = Object.entries(all).filter(([n, p]) => n !== 'GLOBAL' && Array.isArray(p.all));
    clear(ui.proxies).append(h('h2', 'Выбор узла'));
    if (!groups.length) { ui.proxies.append(h('div', { class: 'empty' }, 'Групп пока нет. Создайте их в разделе «Группы».')); return; }
    for (const [name, g] of groups) {
      const isSel = /^selector$/i.test(g.type);
      const chips = g.all.map((m) => {
        const d = delays[m] !== undefined ? delays[m] : (all[m] && all[m].history && all[m].history.length ? all[m].history[all[m].history.length - 1].delay : undefined);
        const lab = d === undefined ? '' : d > 0 ? d + ' мс' : 'сбой';
        const c = h('button', {
          type: 'button', class: 'chip' + (g.now === m ? ' on' : '') + (d > 0 && d < 500 ? ' good' : d === 0 ? ' bad' : ''), disabled: !isSel,
          'aria-pressed': g.now === m ? 'true' : 'false', title: isSel ? 'Выбрать' : 'Группа выбирает узел автоматически',
          onclick: async () => {
            try { await put('api/clash/proxies/' + encodeURIComponent(name), { name: m }); g.now = m; drawProxies(all); } catch (e) { toastErr(e); }
          },
        }, m, h('small', lab));
        return c;
      });
      const testAll = h('button', { class: 'btn sm', onclick: async () => {
        testAll.disabled = true; testAll.textContent = 'Проверка…';
        const queue = g.all.slice();
        const worker = async () => { while (queue.length && alive) { const m = queue.shift(); await testDelay(m); } };
        await Promise.all([worker(), worker(), worker(), worker()]);
        if (alive) drawProxies(all);
      } }, 'Проверить задержку');
      ui.proxies.append(h('div', { style: 'margin-bottom:12px' },
        h('div', { class: 'row', style: 'margin-bottom:6px' }, h('b', name), badge(g.type), h('span', { class: 'small mute' }, 'сейчас: ' + (g.now || '—')), h('span', { class: 'grow' }), testAll),
        h('div', { class: 'chips' }, chips)));
    }
  }
  async function testDelay(name) {
    try {
      const r = await get('api/clash/proxies/' + encodeURIComponent(name) + '/delay?url=' + encodeURIComponent(TEST_URL) + '&timeout=5000', { signal: ctl.signal });
      delays[name] = (r && r.delay) || 0;
    } catch (e) { delays[name] = 0; }
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
    if (run && clashOn !== true) { clashOn = true; buildClash(); loadProxies(); startTraffic(); loadConns(); }
    else if (!run && clashOn !== false) drawOff();
  }

  async function refresh() { try { await st.loadStatus(); } catch (e) { /* покажем старое */ } paint(); }
  function paint() { if (!alive) return; drawSvc(); drawPend(); drawPlat(); syncClash(); }
  const unsub = st.subscribe(() => { if (alive) { drawPend(); } });
  let tick = 0;
  paint();
  timers.push(setInterval(() => { if (!document.hidden) { refresh(); if (clashOn) { loadConns(); startTraffic(); if (++tick % 8 === 0) loadProxies(); } } }, 2500));
  return () => { stop(); unsub(); };
}
