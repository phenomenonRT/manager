import { h, clear, toast, toastErr, spinner, note, onEdit } from './ui.js';
import { get, post, setAuthHandler } from './api.js';
import * as st from './state.js';

const S = st.S;
const ROUTES = [
  ['dashboard', 'Обзор'], ['nodes', 'Узлы и VPN'], ['groups', 'Группы'],
  ['routing', 'Маршрутизация'], ['dns', 'DNS'], ['network', 'Входящие, TUN, сеть'],
  ['config', 'Конфигурация'], ['logs', 'Логи'], ['components', 'Компоненты'], ['system', 'Система'],
];
const app = document.getElementById('app');
let main = null, barEl = null, statusTimer = 0, cleanup = null, token = 0, started = false, unsub = null;

function stopApp() {
  started = false; clearInterval(statusTimer);
  if (cleanup) { try { cleanup(); } catch (e) { /* ignore */ } cleanup = null; }
  if (unsub) { unsub(); unsub = null; }
  token++;
  document.body.classList.remove('nav');
}

async function showLogin(force) {
  stopApp();
  clear(app);
  const m = await import('./pages/login.js');
  m.login(app, S.session, boot, !!force);
}
window.addEventListener('cp-fixed', (e) => toast('Исправлено автоматически: ' + e.detail.join('; ') + '. Сохраните настройки.', 'ok', 12000));
let recheck = false;
// 401 может прийти не из-за сессии (например, от ядра) — сначала уточняем у панели.
setAuthHandler(async () => {
  if (!started || recheck) return;
  recheck = true;
  try {
    const s = await get('api/session', { noAuth: true });
    if (s.authenticated) return;
    toast('Сессия истекла, войдите заново', 'err');
    S.session = { authenticated: false };
    showLogin();
  } catch (e) { /* панель недоступна — не считаем это выходом */ }
  finally { recheck = false; }
});

async function boot() {
  clear(app).append(h('p', { class: 'boot' }, 'Загрузка…'));
  try { S.session = await get('api/session', { noAuth: true }); }
  catch (e) {
    clear(app).append(h('div', { class: 'login' }, note('err', 'Панель недоступна: ' + e.message), h('button', { class: 'btn', onclick: boot }, 'Повторить')));
    return;
  }
  if (!S.session.authenticated) return showLogin();
  try { await Promise.all([st.loadSystem(), st.loadSettings(), st.loadStatus().catch(() => {})]); }
  catch (e) {
    if (e.status === 401) return;
    clear(app).append(h('div', { class: 'login' }, note('err', 'Не удалось загрузить настройки: ' + e.message), h('button', { class: 'btn', onclick: boot }, 'Повторить')));
    return;
  }
  await st.fixDnsListen();
  st.pruneRefs(); // чинит ссылки на удалённые узлы в уже сохранённых настройках
  startApp();
}

// ---- тема ----
const THEMES = [['', 'авто'], ['light', 'светлая'], ['dark', 'тёмная']];
function curTheme() { try { return localStorage.getItem('cp-theme') || ''; } catch (e) { return ''; } }
function cycleTheme(btn) {
  const i = (THEMES.findIndex((t) => t[0] === curTheme()) + 1) % THEMES.length;
  const v = THEMES[i][0];
  try { v ? localStorage.setItem('cp-theme', v) : localStorage.removeItem('cp-theme'); } catch (e) { /* ignore */ }
  if (v) document.documentElement.setAttribute('data-theme', v); else document.documentElement.removeAttribute('data-theme');
  btn.textContent = 'Тема: ' + THEMES[i][1];
}

function startApp() {
  started = true;
  const themeBtn = h('button', { class: 'btn sm ghost', title: 'Переключить тему', onclick: () => cycleTheme(themeBtn) }, 'Тема: ' + THEMES.find((t) => t[0] === curTheme())[1]);
  const svc = h('a', { href: '#/dashboard', class: 'small', style: 'text-decoration:none;color:inherit' });
  const coreB = h('span', { class: 'badge acc' });
  const verB = h('span', { class: 'ver', title: 'Версия панели' });
  const burger = h('button', { class: 'btn sm icon burger', 'aria-label': 'Меню', onclick: () => document.body.classList.toggle('nav') }, '☰');
  const nav = h('nav', { class: 'side', 'aria-label': 'Разделы' }, ROUTES.map(([id, t]) => h('a', { href: '#/' + id, 'data-r': id, onclick: () => document.body.classList.remove('nav') }, t)));
  main = h('main', { id: 'main', tabindex: '-1' });
  barEl = h('div', { id: 'bar', hidden: true });
  clear(app).append(
    h('header', { class: 'top' }, burger, h('span', { class: 'brand' }, 'core', h('i', 'panel')), coreB, verB, h('span', { class: 'grow' }), svc, themeBtn),
    h('div', { class: 'shell' }, nav, main), h('div', { class: 'scrim', onclick: () => document.body.classList.remove('nav') }), barEl);

  const paint = () => {
    coreB.textContent = st.coreName(S.settings.core);
    const pv = S.system && S.system.panel_version;
    verB.textContent = pv ? 'v' + String(pv).replace(/^v/, '') : '';
    const stt = S.status ? S.status.state : '—';
    const kind = stt === 'running' ? 'ok' : (stt === 'error' || stt === 'failed') ? 'err' : 'warn';
    clear(svc).append(h('span', { class: 'dot ' + kind }), stt === 'running' ? 'работает' : stt === 'stopped' ? 'остановлен' : stt === 'waiting' ? 'ждёт сеть' : stt);
    drawBar();
  };
  unsub = st.subscribe(paint);
  paint();
  statusTimer = setInterval(() => { if (!document.hidden) st.loadStatus().catch(() => {}); }, 5000);
  onEdit(st.touch);
  window.onhashchange = route;
  route();
}

// ---- плавающая панель сохранения ----
async function doSave(apply) {
  try {
    const r = await st.save(apply);
    if (r.applied) toast('Сохранено и применено', 'ok');
    else if (apply) toast('Сохранено, но не применено: исправьте ошибки', 'err');
    else toast('Сохранено. Чтобы изменения вступили в силу, примените их', 'ok');
  } catch (e) { toastErr(e); }
}
function drawBar() {
  if (!barEl) return;
  const dirty = st.isDirty();
  const issues = S.issues;
  if (!dirty && !S.needApply && !issues.length) { barEl.hidden = true; return; }
  barEl.hidden = false;
  const kids = [];
  if (issues.length) {
    kids.push(h('div', { class: 'issues' }, issues.map((i) => h('div', { class: 'note ' + (i.level === 'error' ? 'err' : 'warn') },
      h('b', i.level === 'error' ? 'Ошибка: ' : 'Замечание: '), i.message))));
  }
  const busy = S.busy;
  kids.push(h('div', { class: 'row' },
    h('span', { class: 'grow small' }, busy ? h('span', { class: 'spin' }) : null,
      busy ? 'Выполняется…' : dirty ? 'Есть несохранённые изменения' : S.needApply ? 'Сохранено, но ещё не применено к ядру' : 'Замечания к настройкам'),
    issues.length ? h('button', { class: 'btn sm ghost', onclick: () => { S.issues = []; st.emit(); } }, 'Скрыть замечания') : null,
    dirty ? h('button', { class: 'btn', disabled: busy, onclick: async () => { if (confirm('Отменить все несохранённые изменения?')) { st.revert(); route(); } } }, 'Отменить') : null,
    dirty ? h('button', { class: 'btn', disabled: busy, onclick: () => doSave(false) }, 'Сохранить') : null,
    (dirty || S.needApply) ? h('button', { class: 'btn primary', disabled: busy, onclick: () => doSave(true) }, S.needApply && !dirty ? 'Применить' : 'Сохранить и применить') : null));
  clear(barEl).append(...kids);
}
window.addEventListener('beforeunload', (e) => { if (started && st.isDirty()) { e.preventDefault(); e.returnValue = ''; } });

// ---- маршрутизатор ----
async function route() {
  if (!started) return;
  const name = (location.hash.replace(/^#\/?/, '') || 'dashboard').split('?')[0];
  const def = ROUTES.find((r) => r[0] === name) || ROUTES[0];
  const my = ++token;
  document.body.classList.remove('nav');
  if (cleanup) { try { cleanup(); } catch (e) { /* ignore */ } cleanup = null; }
  document.querySelectorAll('.side a').forEach((a) => (a.getAttribute('data-r') === def[0] ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
  clear(main).append(spinner());
  try {
    const mod = await import('./pages/' + def[0] + '.js');
    if (my !== token) return;
    const box = h('div');
    clear(main).append(box);
    const c = await mod.default(box, { route, go: (r) => { location.hash = '#/' + r; } });
    if (my !== token) { if (c) c(); return; }
    cleanup = c || null;
    document.title = def[1] + ' — corepanel';
  } catch (e) {
    if (my !== token || e.status === 401) return;
    clear(main).append(note('err', 'Ошибка загрузки раздела: ' + e.message), h('button', { class: 'btn', onclick: route }, 'Повторить'));
  }
}

boot();
