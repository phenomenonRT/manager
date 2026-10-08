import { h, clear, txt, pw, field, note, toast } from '../ui.js';
import { post } from '../api.js';

export function login(root, session, done, mustChange) {
  const box = h('div', { class: 'login' });
  clear(root).append(box);
  const err = h('div');
  const showErr = (m) => clear(err).append(m ? note('err', m) : '');
  const brand = h('h1', { class: 'brand', style: 'font-size:22px;margin-bottom:12px' }, 'core', h('i', 'panel'));

  if (!mustChange) {
    const f = { username: 'admin', password: '' };
    const form = h('form', {
      class: 'card', onsubmit: async (e) => {
        e.preventDefault(); showErr('');
        try { await post('api/login', { username: f.username, password: f.password }, { noAuth: true }); done(); }
        catch (x) { showErr(x.message); }
      },
    }, h('h2', 'Вход'), err,
    field('Пользователь', txt(f, 'username', { ph: 'admin' })),
    field('Пароль', pw(f, 'password')),
    h('button', { class: 'btn primary', type: 'submit', style: 'width:100%' }, 'Войти'));
    box.append(brand, form);
    form.querySelector('input[type=password]').focus();
    return;
  }
  const f = { old: '', n1: '', n2: '' };
  const form = h('form', {
    class: 'card', onsubmit: async (e) => {
      e.preventDefault(); showErr('');
      if (f.n1.length < 8) return showErr('Новый пароль должен быть не короче 8 символов');
      if (f.n1 !== f.n2) return showErr('Пароли не совпадают');
      try { await post('api/password', { old: f.old, new: f.n1 }); toast('Пароль изменён', 'ok'); done(); }
      catch (x) { showErr(x.message); }
    },
  }, h('h2', 'Смена пароля'), note('warn', 'Это первый вход: задайте собственный пароль, чтобы продолжить.'), err,
  field('Текущий пароль', pw(f, 'old')), field('Новый пароль (от 8 символов)', pw(f, 'n1')), field('Повторите новый пароль', pw(f, 'n2')),
  h('button', { class: 'btn primary', type: 'submit', style: 'width:100%' }, 'Сменить пароль'));
  box.append(brand, form);
}
