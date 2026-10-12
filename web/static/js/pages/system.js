import { apd, h, pageHead, field, pw, note, toast, toastErr, txt, confirmBox, chk, clear } from '../ui.js';
import { get, post } from '../api.js';
import * as st from '../state.js';

// внешняя ссылка: в новой вкладке, без передачи адреса панели
const ext = (href, text) => h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, text);

export default async function (root) {
  const S = st.S;
  const a = { password: '' };
  const l = { listen: (S.system && S.system.listen) || '' };
  const msg = h('div');
  const show = (n) => msg.replaceChildren(n || '');
  const authCard = () => {
    const on = !!(S.session && S.session.auth_enabled);
    const toggle = async (enabled) => {
      show('');
      try {
        const r = await post('api/auth', { enabled, password: a.password });
        S.session = Object.assign({}, S.session, { auth_enabled: r.auth_enabled });
        toast(enabled ? 'Вход по паролю root включён' : 'Вход выключен', 'ok');
        a.password = ''; location.reload();
      } catch (x) { show(note('err', x.message)); }
    };
    return on
      ? h('div', { class: 'card' }, h('h2', 'Вход в панель'), msg,
        note('ok', 'Вход включён: нужен пароль root (как для SSH).'),
        h('button', { class: 'btn', onclick: async () => { if (await confirmBox('Выключить вход? Панель станет доступна без пароля устройствам локальной сети.', 'Выключить')) toggle(false); } }, 'Выключить вход'))
      : h('form', { class: 'card', onsubmit: (e) => { e.preventDefault(); toggle(true); } }, h('h2', 'Вход в панель'), msg,
        note('', 'Сейчас панель открывается без пароля, но только из локальной сети. Чтобы включить вход, подтвердите пароль root — тот же, что у вас для SSH.'),
        field('Пароль root', pw(a, 'password'), 'Если пароль root не задан, выполните по SSH команду passwd. Забыли пароль — по SSH: corepanel auth off.'),
        h('button', { class: 'btn primary', type: 'submit' }, 'Включить вход'));
  };
  // ---- обновление панели ----
  const updBox = h('div', { class: 'card' });
  let alive = true, updT = 0, applying = false;
  const fmtTime = (t) => (t ? new Date(t * 1000).toLocaleString('ru-RU') : 'ещё не проверялось');
  function drawUpd(u) {
    S.update = u;
    clear(updBox);
    const j = u.job || {};
    const busy = !!j.running || applying;
    apd(updBox, h('h2', 'Обновление'),
      h('dl', { class: 'kv' }, h('dt', 'Установлена'), h('dd', 'v' + String(u.current || '—').replace(/^v/, '')),
        h('dt', 'Последняя версия'), h('dd', u.latest ? 'v' + u.latest : '—'),
        h('dt', 'Проверено'), h('dd', fmtTime(u.checked_at))),
      u.available ? note('ok', 'Доступна новая версия v' + u.latest + '.') : (u.latest ? note('', 'Установлена последняя версия.') : null),
      u.reason ? note(u.available ? 'warn' : 'err', u.reason) : null,
      j.error ? note('err', j.error) : null,
      h('div', { class: 'row', style: 'flex-wrap:wrap;gap:8px;margin:10px 0' },
        h('button', { class: 'btn', disabled: busy, onclick: async () => {
          try { drawUpd(await post('api/update/check')); } catch (x) { toastErr(x); }
        } }, 'Проверить обновления'),
        u.available && u.can_apply ? h('button', { class: 'btn primary', disabled: busy, onclick: async () => {
          if (!(await confirmBox('Обновить панель до v' + u.latest + '? Ядро будет остановлено и запущено снова, страница перезагрузится.', 'Обновить'))) return;
          try { applying = true; drawUpd(await post('api/update/apply')); watch(u.current); } catch (x) { applying = false; toastErr(x); }
        } }, 'Обновить до v' + u.latest) : null,
        u.page_url ? h('a', { class: 'btn ghost', href: u.page_url, target: '_blank', rel: 'noopener noreferrer' }, 'Что нового') : null),
      chk(S.settings.update, 'auto', 'Автообновление', 'Раз в несколько часов панель проверяет релизы на GitHub и сама ставит новую версию (ядро при этом ненадолго перезапускается). По умолчанию выключено. Сохраните настройки, чтобы изменение вступило в силу.'),
      (j.running || (j.output && j.output.length)) ? h('pre', { class: 'mono', style: 'max-height:200px;overflow:auto;white-space:pre-wrap;margin-top:10px' }, (j.output || []).join('\n')) : null);
  }
  // после замены файла панель перезапускается: ждём, пока она снова ответит с новой версией
  function watch(prevVersion) {
    clearTimeout(updT);
    const tick = async () => {
      if (!alive) return;
      try {
        const u = await get('api/update');
        if (u.current && u.current !== prevVersion) { toast('Панель обновлена до v' + u.current, 'ok'); setTimeout(() => location.reload(), 600); return; }
        if (u.job && u.job.finished && u.job.error) { applying = false; drawUpd(u); return; }
        drawUpd(u);
      } catch (x) { /* панель перезапускается */ }
      updT = setTimeout(tick, 1500);
    };
    updT = setTimeout(tick, 1500);
  }
  get('api/update').then(async (u) => {
    if (!alive) return;
    drawUpd(u);
    if (!u.checked_at && !(u.job && u.job.running)) { const c = await post('api/update/check'); if (alive) drawUpd(c); }
  }).catch(() => {});

  apd(root, pageHead('Система', 'Параметры самой панели'),
    h('div', { class: 'card' }, h('h2', 'О панели'), h('dl', { class: 'kv' },
      h('dt', 'Версия'), h('dd', (S.system && S.system.panel_version) || '—'), h('dt', 'Вход'), h('dd', S.session && S.session.auth_enabled ? 'по паролю root' : 'без пароля (только из локальной сети)'),
      h('dt', 'Каталог данных'), h('dd', { class: 'mono' }, (S.system && S.system.platform && S.system.platform.data_dir) || '—'),
      h('dt', 'Проект на GitHub'), h('dd', { class: 'links' },
        ext('https://github.com/phenomenonRT/panel_awg-box_sing-box', 'Исходный код и описание'),
        ext('https://github.com/phenomenonRT/panel_awg-box_sing-box/releases', 'Релизы'),
        ext('https://github.com/phenomenonRT/panel_awg-box_sing-box/issues', 'Сообщить о проблеме')))),
    updBox,
    h('div', { class: 'cols' },
      authCard(),
      h('div', { class: 'card' }, h('h2', 'Адрес панели'),
        field('Слушать на', txt(l, 'listen', { ph: '0.0.0.0:8088' }), 'Адрес и порт веб-интерфейса. 127.0.0.1 — только с самого роутера; 0.0.0.0 — из всей сети. После смены панель перезапустится на новом адресе, а эта страница может перестать открываться.'),
        h('button', { class: 'btn', onclick: async () => {
          if (!l.listen.trim()) return toast('Укажите адрес', 'err');
          if (!(await confirmBox('Сменить адрес панели на ' + l.listen + '? Откройте панель по новому адресу.', 'Сменить', false))) return;
          try { await post('api/panel', { listen: l.listen.trim() }); toast('Адрес сохранён. Откройте панель по новому адресу.', 'ok', 9000); } catch (x) { toastErr(x); }
        } }, 'Применить адрес')),
      !(S.session && S.session.auth_enabled) ? null : h('div', { class: 'card' }, h('h2', 'Сессия'),
        h('button', { class: 'btn danger', onclick: async () => {
          if (st.isDirty() && !(await confirmBox('Есть несохранённые изменения. Выйти без сохранения?', 'Выйти'))) return;
          try { await post('api/logout'); } catch (x) { /* всё равно выходим */ }
          location.hash = ''; location.reload();
        } }, 'Выйти'))));
  return () => { alive = false; clearTimeout(updT); };
}
