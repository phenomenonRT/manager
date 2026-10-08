import { apd, h, clear, pageHead, note, spinner, toast, toastErr, download, copy, errMsg, confirmBox } from '../ui.js';
import { post } from '../api.js';
import * as st from '../state.js';

const S = st.S;
const span = (c, t) => h('span', { class: c }, t);

export function hlJSON(text) {
  const frag = document.createDocumentFragment();
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) frag.append(text.slice(last, m.index));
    if (m[1]) { frag.append(span(m[2] ? 'k' : 's', m[1])); if (m[2]) frag.append(m[2]); }
    else frag.append(span(m[3] ? 'b' : 'n', m[0]));
    last = re.lastIndex;
  }
  frag.append(text.slice(last));
  return frag;
}
function hlValue(v) {
  const t = v.trim();
  if (!t) return v;
  const lead = v.slice(0, v.indexOf(t));
  if (t[0] === '#') return [lead, span('c', t)];
  const ci = t.search(/\s#/);
  const body = ci >= 0 ? t.slice(0, ci) : t, com = ci >= 0 ? t.slice(ci) : '';
  let cls = '';
  if (/^(".*"|'.*')$/.test(body)) cls = 's'; else if (/^(true|false|null|~)$/.test(body)) cls = 'b'; else if (/^-?\d+(\.\d+)?$/.test(body)) cls = 'n';
  return [lead, cls ? span(cls, body) : body, com ? span('c', com) : ''];
}
export function hlYAML(text) {
  const frag = document.createDocumentFragment();
  const ls = text.split('\n');
  ls.forEach((ln, i) => {
    const m = /^(\s*(?:-\s+)?)([^\s#:'"{}\[\],&*!|>%@`][^:#]*?|"[^"]*"|'[^']*')(:)(\s.*|)$/.exec(ln);
    if (/^\s*#/.test(ln)) frag.append(span('c', ln));
    else if (m) frag.append(m[1], span('k', m[2]), m[3], ...[].concat(hlValue(m[4])));
    else { const d = /^(\s*-\s+)(.*)$/.exec(ln); if (d) frag.append(d[1], ...[].concat(hlValue(d[2]))); else frag.append(ln); }
    if (i < ls.length - 1) frag.append('\n');
  });
  return frag;
}

function fillDefaults(imp) {
  // Импорт: подставляем недостающие поля из текущей структуры (секции, массивы).
  const base = st.normalize({});
  st.fill(imp, base);
  return st.normalize(imp);
}

export default async function (root) {
  const s = S.settings;
  const out = h('div');
  let last = null;

  async function render(btn) {
    if (btn) btn.disabled = true;
    clear(out).append(spinner('Генерация…'));
    try {
      const r = await post('api/render', s);
      last = r;
      const isJSON = (r.filename || '').endsWith('.json') || r.core === 'singbox';
      const pre = h('pre', { class: 'code' });
      pre.append(isJSON ? hlJSON(r.config) : hlYAML(r.config));
      clear(out).append(
        (r.warnings && r.warnings.length) ? note('warn', h('b', 'Предупреждения:'), h('ul', r.warnings.map((w) => h('li', w)))) : note('ok', 'Конфигурация сформирована без предупреждений.'),
        h('div', { class: 'row', style: 'margin-bottom:8px' }, h('b', { class: 'mono' }, r.filename || 'config'),
          h('span', { class: 'grow' }),
          h('button', { class: 'btn sm', onclick: () => copy(r.config) }, 'Копировать'),
          h('button', { class: 'btn sm', onclick: () => download(r.filename || 'config', r.config, isJSON ? 'application/json' : 'text/yaml') }, 'Скачать')),
        pre);
    } catch (e) { clear(out).append(note('err', 'Не удалось сформировать: ' + errMsg(e))); }
    if (btn) btn.disabled = false;
  }

  // ---- расширенные добавки ----
  function overrideEditor(key, title, hint) {
    const obj = s[key];
    const status = h('span', { class: 'small' });
    const ta = h('textarea', {
      rows: 8, spellcheck: 'false', 'aria-label': title, value: obj && Object.keys(obj).length ? JSON.stringify(obj, null, 2) : '', placeholder: '{\n  "ключ": "значение"\n}',
      oninput: () => {
        const t = ta.value.trim();
        if (!t) { delete s[key]; status.textContent = 'пусто'; status.style.color = ''; st.touch(); return; }
        try {
          const v = JSON.parse(t);
          if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('нужен JSON-объект {…}');
          s[key] = v; status.textContent = 'JSON корректен'; status.style.color = 'var(--ok)'; st.touch();
        } catch (e) { status.textContent = 'Ошибка: ' + e.message; status.style.color = 'var(--err)'; }
      },
    });
    return h('div', { class: 'card' }, h('div', { class: 'row' }, h('h2', { style: 'margin:0' }, title), s.core === (key === 'override_mihomo' ? 'mihomo' : 'singbox') ? h('span', { class: 'badge acc' }, 'активно') : h('span', { class: 'badge' }, 'другое ядро'), h('span', { class: 'grow' }), status),
      h('p', { class: 'small mute', style: 'margin:6px 0' }, hint), ta);
  }

  const fileIn = h('input', { type: 'file', accept: 'application/json,.json', 'aria-label': 'Файл настроек', onchange: async (e) => {
    const f = e.target.files[0]; e.target.value = '';
    if (!f) return;
    try {
      const imp = JSON.parse(await f.text());
      if (!imp || typeof imp !== 'object' || Array.isArray(imp) || !('nodes' in imp || 'general' in imp || 'core' in imp)) throw new Error('это не файл настроек corepanel');
      if (!(await confirmBox('Заменить текущие настройки содержимым файла? (потребуется сохранить)', 'Заменить', false))) return;
      S.settings = fillDefaults(imp); st.touch(); toast('Настройки загружены. Проверьте и сохраните.', 'ok');
      location.hash = '#/dashboard'; setTimeout(() => { location.hash = '#/config'; }, 0);
    } catch (x) { toastErr(x); }
  } });

  const btn = h('button', { class: 'btn primary' }, 'Обновить');
  btn.onclick = () => render(btn);
  apd(root, pageHead('Конфигурация', 'Итоговый конфиг ядра, расширенные добавки и перенос настроек'),
    h('div', { class: 'card' }, h('div', { class: 'row', style: 'margin-bottom:10px' }, h('h2', { style: 'margin:0' }, 'Сгенерированный конфиг'), h('span', { class: 'grow' }), btn),
      h('p', { class: 'small mute' }, 'Строится из текущих, в том числе несохранённых, настроек. Секреты показываются как есть — не публикуйте конфиг.'), out),
    overrideEditor('override_singbox', 'Расширенные добавки: sing-box', 'JSON-объект, который глубоко сливается с итоговым конфигом sing-box (объекты объединяются, списки и значения заменяются). Позволяет использовать возможности, для которых нет полей в панели.'),
    overrideEditor('override_mihomo', 'Расширенные добавки: Mihomo', 'JSON-объект, который глубоко сливается с итоговым YAML Mihomo. Например: {"tun": {"device": "utun0"}}.'),
    h('div', { class: 'card' }, h('h2', 'Импорт и экспорт настроек'),
      h('p', { class: 'small mute' }, 'Файл содержит все настройки, включая пароли и ключи узлов, — храните его в безопасном месте.'),
      h('div', { class: 'row' }, h('button', { class: 'btn', onclick: () => download('settings.json', JSON.stringify(s, null, 2)) }, 'Скачать settings.json'), fileIn)));
  render();
}
