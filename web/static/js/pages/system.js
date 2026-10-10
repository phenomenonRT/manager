import { apd, h, pageHead, field, pw, note, toast, toastErr, txt, confirmBox } from '../ui.js';
import { post } from '../api.js';
import * as st from '../state.js';

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
  apd(root, pageHead('Система', 'Параметры самой панели'),
    h('div', { class: 'card' }, h('h2', 'О панели'), h('dl', { class: 'kv' },
      h('dt', 'Версия'), h('dd', (S.system && S.system.panel_version) || '—'), h('dt', 'Вход'), h('dd', S.session && S.session.auth_enabled ? 'по паролю root' : 'без пароля (только из локальной сети)'),
      h('dt', 'Каталог данных'), h('dd', { class: 'mono' }, (S.system && S.system.platform && S.system.platform.data_dir) || '—'))),
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
}
