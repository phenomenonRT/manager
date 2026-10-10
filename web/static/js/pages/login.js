import { h, clear, pw, field, note } from '../ui.js';
import { post } from '../api.js';

// Вход нужен только если включён в разделе «Система»; пароль — тот же, что у root по SSH.
export function login(root, session, done) {
  const box = h('div', { class: 'login' });
  clear(root).append(box);
  const err = h('div');
  const showErr = (m) => clear(err).append(m ? note('err', m) : '');
  const brand = h('h1', { class: 'brand', style: 'font-size:22px;margin-bottom:12px' }, 'core', h('i', 'panel'));
  const f = { password: '' };
  const form = h('form', {
    class: 'card', onsubmit: async (e) => {
      e.preventDefault(); showErr('');
      try { await post('api/login', { username: 'root', password: f.password }, { noAuth: true }); done(); }
      catch (x) { showErr(x.message); }
    },
  }, h('h2', 'Вход'), err,
  field('Пароль root', pw(f, 'password'), 'Тот же пароль, что и для входа на роутер по SSH.'),
  h('button', { class: 'btn primary', type: 'submit', style: 'width:100%' }, 'Войти'));
  box.append(brand, form);
  form.querySelector('input[type=password]').focus();
}
