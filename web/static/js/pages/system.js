import { apd, h, pageHead, field, pw, note, toast, toastErr, txt, confirmBox } from '../ui.js';
import { post } from '../api.js';
import * as st from '../state.js';

export default async function (root) {
  const S = st.S;
  const p = { old: '', n1: '', n2: '' };
  const l = { listen: (S.system && S.system.listen) || '' };
  const msg = h('div');
  const show = (n) => msg.replaceChildren(n || '');
  apd(root, pageHead('Система', 'Параметры самой панели'),
    h('div', { class: 'card' }, h('h2', 'О панели'), h('dl', { class: 'kv' },
      h('dt', 'Версия'), h('dd', (S.system && S.system.panel_version) || '—'), h('dt', 'Пользователь'), h('dd', (S.session && S.session.user) || '—'),
      h('dt', 'Каталог данных'), h('dd', { class: 'mono' }, (S.system && S.system.platform && S.system.platform.data_dir) || '—'))),
    h('div', { class: 'cols' },
      h('form', { class: 'card', onsubmit: async (e) => {
        e.preventDefault(); show('');
        if (p.n1.length < 8) return show(note('err', 'Новый пароль должен быть не короче 8 символов'));
        if (p.n1 !== p.n2) return show(note('err', 'Пароли не совпадают'));
        try { await post('api/password', { old: p.old, new: p.n1 }); toast('Пароль изменён', 'ok'); p.old = p.n1 = p.n2 = ''; e.target.reset(); } catch (x) { show(note('err', x.message)); }
      } }, h('h2', 'Смена пароля'), msg,
      field('Текущий пароль', pw(p, 'old')), field('Новый пароль', pw(p, 'n1')), field('Повторите новый пароль', pw(p, 'n2')),
      h('button', { class: 'btn primary', type: 'submit' }, 'Сменить пароль')),
      h('div', { class: 'card' }, h('h2', 'Адрес панели'),
        field('Слушать на', txt(l, 'listen', { ph: '0.0.0.0:8088' }), 'Адрес и порт веб-интерфейса. 127.0.0.1 — только с самого роутера; 0.0.0.0 — из всей сети. После смены панель перезапустится на новом адресе, а эта страница может перестать открываться.'),
        h('button', { class: 'btn', onclick: async () => {
          if (!l.listen.trim()) return toast('Укажите адрес', 'err');
          if (!(await confirmBox('Сменить адрес панели на ' + l.listen + '? Откройте панель по новому адресу.', 'Сменить', false))) return;
          try { await post('api/panel', { listen: l.listen.trim() }); toast('Адрес сохранён. Откройте панель по новому адресу.', 'ok', 9000); } catch (x) { toastErr(x); }
        } }, 'Применить адрес')),
      h('div', { class: 'card' }, h('h2', 'Сессия'),
        h('button', { class: 'btn danger', onclick: async () => {
          if (st.isDirty() && !(await confirmBox('Есть несохранённые изменения. Выйти без сохранения?', 'Выйти'))) return;
          try { await post('api/logout'); } catch (x) { /* всё равно выходим */ }
          location.hash = ''; location.reload();
        } }, 'Выйти'))));
}
