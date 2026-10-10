import { apd, h, clear, pageHead, badge, note, field, fgrid, txt, num, pw, lines, csv, sel, chk, area, modal, confirmBox, toast, toastErr, help } from '../ui.js';
import { get, post } from '../api.js';
import * as st from '../state.js';

const S = st.S;
export const TYPES = [['vless', 'VLESS'], ['vmess', 'VMess'], ['trojan', 'Trojan'], ['shadowsocks', 'Shadowsocks'], ['hysteria2', 'Hysteria2'], ['tuic', 'TUIC'], ['wireguard', 'WireGuard'], ['awg', 'AmneziaWG'], ['socks', 'SOCKS5'], ['http', 'HTTP']];
const TYPE_NAME = Object.fromEntries(TYPES);
const SS_METHODS = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305', 'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305', 'none'];
let ifacePromise = null;
const ifaces = () => (ifacePromise = ifacePromise || get('api/interfaces').catch(() => []));

export default async function (root) {
  const s = S.settings;
  const tableBox = h('div');
  const vpnBox = h('div');

  function drawTable() {
    clear(tableBox);
    if (!s.nodes.length) { tableBox.append(h('div', { class: 'empty' }, 'Узлов пока нет. Импортируйте ссылки или подписку ниже, либо добавьте узел вручную.')); return; }
    tableBox.append(h('div', { class: 'tw' }, h('table',
      h('thead', h('tr', h('th', 'Вкл'), h('th', 'Имя'), h('th', 'Тип'), h('th', 'Сервер:порт'), h('th', ''))),
      h('tbody', s.nodes.map((n, i) => h('tr', { class: n.disabled ? 'off' : '' },
        h('td', h('input', { type: 'checkbox', checked: !n.disabled, 'aria-label': 'Включить ' + n.name, onchange: (e) => { n.disabled = !e.target.checked; st.touch(); drawTable(); } })),
        h('td', n.name, n.detour ? h('div', { class: 'small mute' }, '→ через ' + n.detour) : null),
        h('td', badge(TYPE_NAME[n.type] || n.type)),
        h('td', { class: 'mono' }, n.server + ':' + n.port),
        h('td', { class: 'act' },
          h('button', { class: 'btn sm', onclick: () => editNode(i) }, 'Изменить'), ' ',
          h('button', { class: 'btn sm', title: 'Дублировать', onclick: () => dup(i) }, '⧉'), ' ',
          h('button', { class: 'btn sm danger', 'aria-label': 'Удалить ' + n.name, onclick: () => del(i) }, '✕'))))))));
  }
  function takenNames() { return new Set([...s.nodes.map((n) => n.name), ...s.groups.map((g) => g.name)]); }
  function dup(i) {
    const c = JSON.parse(JSON.stringify(s.nodes[i]));
    c.name = st.uniqueName(c.name + ' копия', takenNames());
    s.nodes.splice(i + 1, 0, c); st.touch(); redraw();
  }
  async function del(i) {
    const n = s.nodes[i];
    const used = s.groups.filter((g) => g.members.includes(n.name)).map((g) => g.name);
    const msg = 'Удалить узел «' + n.name + '»?' + (used.length ? ' Он будет убран из групп: ' + used.join(', ') + '.' : '');
    if (!(await confirmBox(msg))) return;
    for (const g of s.groups) g.members = g.members.filter((m) => m !== n.name);
    for (const x of s.nodes) if (x.detour === n.name) x.detour = '';
    s.nodes.splice(i, 1); st.pruneRefs(); st.touch(); redraw();
  }
  function redraw() { drawTable(); drawVpn(); }

  // ---- импорт ----
  const imp = { text: '', url: '' };
  const impRes = h('div');
  function applyImport(r) {
    const nodes = (r && r.nodes) || [], errors = (r && r.errors) || [];
    const taken = takenNames();
    for (const n of nodes) { n.name = st.uniqueName(n.name || (n.server + ':' + n.port), taken); taken.add(n.name); s.nodes.push(n); }
    if (nodes.length) { st.touch(); redraw(); }
    clear(impRes).append(
      nodes.length ? note('ok', 'Добавлено узлов: ' + nodes.length + '. Не забудьте сохранить настройки.') : note('warn', 'Ни одного узла не распознано.'),
      errors.length ? note('err', h('b', 'Не удалось разобрать (' + errors.length + '):'), h('ul', errors.map((e) => h('li', { class: 'mono' }, e)))) : null);
  }
  const runImport = (btn, fn) => async () => {
    btn.disabled = true;
    try { applyImport(await fn()); } catch (e) { toastErr(e); }
    btn.disabled = false;
  };
  const ta = area(imp, 'text', { rows: 5, ph: 'vless://…\nvmess://…\ntrojan://…\nss://…\nhysteria2://…\ntuic://…\nили подписка в base64, или содержимое WireGuard .conf' });
  const bText = h('button', { class: 'btn primary' }, 'Разобрать и добавить');
  bText.onclick = runImport(bText, () => { if (!imp.text.trim()) throw new Error('Вставьте ссылки или конфигурацию'); return post('api/import', { text: imp.text }); });
  const fileIn = h('input', { type: 'file', accept: '.conf,.txt,text/plain', 'aria-label': 'Файл конфигурации', onchange: async (e) => { const f = e.target.files[0]; if (f) { ta.value = imp.text = await f.text(); e.target.value = ''; } } });
  const urlIn = txt(imp, 'url', { ph: 'https://example.com/sub?token=…' });
  const bUrl = h('button', { class: 'btn' }, 'Загрузить подписку');
  bUrl.onclick = runImport(bUrl, () => { if (!imp.url.trim()) throw new Error('Укажите URL подписки'); return post('api/import/url', { url: imp.url.trim() }); });

  // ---- VPN-интерфейсы ----
  function drawVpn() {
    clear(vpnBox);
    const wg = s.nodes.filter((n) => n.type === 'wireguard' || n.type === 'awg');
    vpnBox.append(h('div', { class: 'card' }, h('h2', 'VPN-интерфейсы (WireGuard)'),
      h('p', 'Узел WireGuard по умолчанию — обычный исходящий: трафик попадает в него только по правилам маршрутизации. Если включить «Системный интерфейс» (',
        h('code', 'system=true'), '), sing-box создаст настоящий сетевой интерфейс wg в ОС — его можно использовать в маршрутах роутера и других программах.'),
      note('warn', 'Системный интерфейс поддерживает только sing-box и требует прав root. В Mihomo WireGuard работает как обычный исходящий, флаг игнорируется.'),
      wg.length ? h('div', { class: 'tw' }, h('table', h('thead', h('tr', h('th', 'Узел'), h('th', 'Адреса'), h('th', 'Системный интерфейс'))),
        h('tbody', wg.map((n) => h('tr', h('td', n.name, n.type === 'awg' ? badge('AWG') : null), h('td', { class: 'mono' }, (n.addresses || []).join(', ') || '—'),
          h('td', h('label', { class: 'check', style: 'margin:0' }, h('input', { type: 'checkbox', checked: !!n.system, onchange: (e) => { n.system = e.target.checked; st.touch(); } }), 'создавать')))))))
        : h('p', { class: 'mute' }, 'WireGuard-узлов нет. Импортируйте .conf или добавьте узел вручную.'),
      h('div', { class: 'row', style: 'margin-top:10px' }, h('button', { class: 'btn', onclick: () => editNode(-1, 'wireguard') }, 'Добавить WireGuard'), h('button', { class: 'btn', onclick: () => editNode(-1, 'awg') }, 'Добавить AmneziaWG'))));
  }

  apd(root, pageHead('Узлы и VPN', 'Прокси-серверы и WireGuard, через которые пойдёт трафик'),
    h('div', { class: 'row', style: 'margin-bottom:10px' }, h('button', { class: 'btn primary', onclick: () => editNode(-1) }, '+ Добавить узел'), h('span', { class: 'mute small' }, 'Узлов: ' + s.nodes.length)),
    tableBox,
    h('div', { class: 'card', style: 'margin-top:14px' }, h('h2', 'Импорт'),
      field('Ссылки, подписка или WireGuard-конфиг', ta, 'Можно вставить несколько ссылок по одной в строке, содержимое подписки (base64) или текст файла .conf.'),
      h('div', { class: 'row', style: 'margin-bottom:12px' }, bText, fileIn),
      h('div', { class: 'row', style: 'align-items:flex-end' }, h('div', { class: 'grow', style: 'min-width:220px' }, field('Подписка по URL', urlIn)), h('div', { style: 'margin-bottom:10px' }, bUrl)),
      impRes),
    vpnBox);
  redraw();

  // ---- редактор узла ----
  async function editNode(idx, type) {
    const isNew = idx < 0;
    const orig = isNew ? null : s.nodes[idx];
    const d = isNew ? { name: '', type: type || 'vless', server: '', port: 443, udp: true } : JSON.parse(JSON.stringify(orig));
    if (isNew) defaults(d);
    const list = await ifaces();
    const body = h('div');
    const dl = h('datalist', { id: 'ifl' }, (list || []).map((i) => h('option', { value: i.name })));
    function build() {
      clear(body).append(dl, nodeForm(d, build));
    }
    build();
    modal({
      title: isNew ? 'Новый узел' : 'Узел «' + orig.name + '»', body, wide: true,
      buttons: [{ text: 'Отмена' }, {
        text: 'Готово', primary: true, onclick: () => {
          d.name = (d.name || '').trim();
          if (!d.name) { toast('Укажите имя узла', 'err'); return false; }
          if (!d.server || !(d.port > 0 && d.port <= 65535)) { toast('Укажите сервер и порт (1–65535)', 'err'); return false; }
          const taken = takenNames(); if (orig) taken.delete(orig.name);
          if (taken.has(d.name)) { toast('Имя «' + d.name + '» уже занято', 'err'); return false; }
          if (!isNew) { st.renameRef(orig.name, d.name); s.nodes[idx] = d; } else s.nodes.push(d);
          st.touch(); redraw();
        },
      }],
    });
  }
}

function defaults(d) {
  if (['trojan', 'hysteria2', 'tuic'].includes(d.type)) d.tls = true;
  if (d.type === 'awg') { d.port = 51820; d.mtu = 1280; d.allowed_ips = ['0.0.0.0/0', '::/0']; d.addresses = []; d.awg = d.awg || { jc: 4, jmin: 40, jmax: 70 }; }
  if (d.type === 'wireguard') { d.port = 51820; d.mtu = 1420; d.allowed_ips = ['0.0.0.0/0', '::/0']; d.addresses = []; }
  if (d.type === 'socks') d.port = 1080;
  if (d.type === 'http') d.port = 8080;
  if (d.type === 'shadowsocks') d.method = d.method || '2022-blake3-aes-128-gcm';
  if (d.type === 'hysteria2') d.port = 443;
}

async function keygen(kind) { return post('api/keygen', { kind }); }

function nodeForm(d, rebuild) {
  const t = d.type;
  const out = h('div');
  const sec = (title, ...c) => h('div', { style: 'margin-top:8px' }, h('h3', title), ...c);
  const typeSel = h('select', { value: t, onchange: (e) => { d.type = e.target.value; defaults(d); rebuild(); } },
    TYPES.map(([v, n]) => h('option', { value: v, selected: v === t }, n)));
  out.append(fgrid(
    field('Имя', txt(d, 'name', { ph: 'Мой узел' }), 'Уникальное имя: без запятых и кавычек, не «direct» и не «block».'),
    field('Тип', typeSel),
    field('Сервер', txt(d, 'server', { ph: 'example.com или IP' })),
    field('Порт', num(d, 'port', { min: 1, max: 65535 }))));

  const uuidBtn = (key) => h('button', { type: 'button', class: 'btn sm', onclick: async () => { try { const r = await keygen('uuid'); d[key] = r.uuid; rebuild(); } catch (e) { toastErr(e); } } }, 'новый');
  const uuidField = () => field('UUID', h('div', { class: 'pw' }, txt(d, 'uuid', { ph: 'xxxxxxxx-xxxx-…' }), uuidBtn('uuid')));

  if (t === 'vless') {
    out.append(fgrid(uuidField(), field('Flow', sel(d, 'flow', [['', 'нет'], ['xtls-rprx-vision', 'xtls-rprx-vision']]), 'xtls-rprx-vision включают вместе с TLS/Reality на tcp-транспорте.')));
  } else if (t === 'vmess') {
    out.append(fgrid(uuidField(), field('Шифрование', sel(d, 'method', [['', 'auto'], 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero'])), field('Alter ID', num(d, 'alter_id', { min: 0 }), 'Для современных серверов — 0.')));
  } else if (t === 'trojan') {
    out.append(fgrid(field('Пароль', pw(d, 'password'))));
  } else if (t === 'shadowsocks') {
    out.append(fgrid(field('Метод шифрования', sel(d, 'method', SS_METHODS)), field('Пароль', pw(d, 'password'))));
  } else if (t === 'hysteria2') {
    out.append(fgrid(field('Пароль', pw(d, 'password')),
      field('Скорость вверх, Мбит/с', num(d, 'up_mbps', { min: 0 }), 'Ограничение исходящей скорости. 0 — не задано (подбирается автоматически).'),
      field('Скорость вниз, Мбит/с', num(d, 'down_mbps', { min: 0 })),
      field('Обфускация', sel(d, 'obfs', [['', 'нет'], 'salamander'], { onchange: rebuild }), 'salamander маскирует QUIC-трафик; пароль должен совпадать с серверным.'),
      d.obfs ? field('Пароль обфускации', pw(d, 'obfs_password')) : null));
  } else if (t === 'tuic') {
    out.append(fgrid(uuidField(), field('Пароль', pw(d, 'password')),
      field('Контроль перегрузки', sel(d, 'congestion', [['', 'по умолчанию'], 'bbr', 'cubic', 'new_reno'])),
      field('Режим UDP relay', sel(d, 'udp_relay_mode', [['', 'по умолчанию'], 'native', 'quic']))));
  } else if (t === 'socks' || t === 'http') {
    out.append(fgrid(field('Логин', txt(d, 'username')), field('Пароль', pw(d, 'password'))));
  } else if (t === 'awg') {
    d.awg = d.awg || {};
    const a = d.awg;
    const gen = h('button', { type: 'button', class: 'btn sm', onclick: async () => {
      try { const r = await keygen('wireguard'); d.private_key = r.private; rebuild(); toast('Публичный ключ для сервера: ' + r.public, 'ok', 15000); } catch (e) { toastErr(e); }
    } }, 'создать пару');
    const hint = S.settings.core === 'amnezia' ? null : note('warn', 'AmneziaWG работает только на ядре amnezia-box. Установите его в разделе «Компоненты» и выберите активным ядром.');
    out.append(sec('AmneziaWG', hint,
      fgrid(field('Приватный ключ', h('div', { class: 'pw' }, pw(d, 'private_key'), gen)),
        field('Публичный ключ пира', txt(d, 'peer_public_key')), field('Pre-shared key', pw(d, 'pre_shared_key')),
        field('Адреса интерфейса', csv(d, 'addresses', { ph: '10.8.0.2/32' })),
        field('Allowed IPs', csv(d, 'allowed_ips', { ph: '0.0.0.0/0, ::/0' })),
        field('MTU', num(d, 'mtu', { min: 0 }))),
      h('h3', { style: 'margin-top:12px' }, 'Обфускация'),
      h('p', { class: 'small mute' }, 'Значения должны совпадать с серверными. Пустое поле или 0 — параметр не передаётся.'),
      fgrid(field('Jc', num(a, 'jc', { min: 0 })), field('Jmin', num(a, 'jmin', { min: 0 })), field('Jmax', num(a, 'jmax', { min: 0 })),
        field('S1', num(a, 's1', { min: 0 })), field('S2', num(a, 's2', { min: 0 })), field('S3', num(a, 's3', { min: 0 })), field('S4', num(a, 's4', { min: 0 })),
        field('H1', txt(a, 'h1', { ph: '123456 или 100-200' })), field('H2', txt(a, 'h2')), field('H3', txt(a, 'h3')), field('H4', txt(a, 'h4')),
        field('I1', txt(a, 'i1', { ph: '<b 0x…>' })), field('I2', txt(a, 'i2')), field('I3', txt(a, 'i3')), field('I4', txt(a, 'i4')), field('I5', txt(a, 'i5')))));
  } else if (t === 'wireguard') {
    const pub = h('div', { class: 'small mono', style: 'word-break:break-all;margin:-4px 0 8px' });
    const gen = h('button', { type: 'button', class: 'btn sm', onclick: async () => {
      try { const r = await keygen('wireguard'); d.private_key = r.private; rebuild(); toast('Публичный ключ для сервера: ' + r.public, 'ok', 15000); } catch (e) { toastErr(e); }
    } }, 'создать пару');
    out.append(sec('WireGuard',
      fgrid(field('Приватный ключ', h('div', { class: 'pw' }, pw(d, 'private_key'), gen), 'Ключ этого устройства. Публичная часть (её показывает кнопка «создать пару») указывается на стороне сервера.'),
        field('Публичный ключ пира', txt(d, 'peer_public_key')), field('Pre-shared key', pw(d, 'pre_shared_key'), 'Необязательный общий секрет пира.'),
        field('Адреса интерфейса', csv(d, 'addresses', { ph: '10.0.0.2/32, fd00::2/128' }), 'Адрес этого клиента внутри VPN, через запятую.'),
        field('Allowed IPs', csv(d, 'allowed_ips', { ph: '0.0.0.0/0, ::/0' }), 'Какие адреса отправлять в туннель. Для полного туннеля: 0.0.0.0/0, ::/0.'),
        field('Reserved (3 числа)', h('input', {
          type: 'text', placeholder: '0, 0, 0', value: (d.reserved || []).join(', '),
          oninput: (e) => { d.reserved = e.target.value.split(/[ ,]+/).filter(Boolean).map((x) => parseInt(x, 10)).filter((x) => x >= 0 && x <= 255); st.touch(); },
        }), 'Нужен для Cloudflare WARP. В остальных случаях оставьте пустым.'),
        field('MTU', num(d, 'mtu', { min: 0 }))),
      pub, chk(d, 'system', 'Создать системный интерфейс (только sing-box)', 'Вместо внутреннего исходящего sing-box создаст настоящий интерфейс wg в ОС. Нужен root.')));
  }

  if (['vless', 'vmess', 'trojan'].includes(t)) {
    const net = d.network || 'tcp';
    out.append(sec('Транспорт', fgrid(
      field('Сеть', sel(d, 'network', [['', 'tcp'], 'ws', 'grpc', 'h2', 'httpupgrade'], { onchange: rebuild }), null),
      ['ws', 'h2', 'httpupgrade'].includes(net) ? field('Path', txt(d, 'path', { ph: '/' })) : null,
      ['ws', 'h2', 'httpupgrade'].includes(net) ? field('Host', txt(d, 'host')) : null,
      net === 'grpc' ? field('Имя сервиса gRPC', txt(d, 'service_name')) : null)));
  }
  const forced = ['trojan', 'hysteria2', 'tuic'].includes(t);
  if (['vless', 'vmess', 'trojan', 'hysteria2', 'tuic', 'http'].includes(t)) {
    const tlsOn = forced || d.tls || d.reality;
    out.append(sec('TLS',
      forced ? null : chk(d, 'tls', 'Включить TLS', null, { onchange: rebuild }),
      tlsOn ? fgrid(
        field('SNI', txt(d, 'sni', { ph: 'server name' })),
        field('ALPN', csv(d, 'alpn', { ph: 'h2, http/1.1' }), 'Через запятую. Для HTTP/3 и QUIC-протоколов обычно h3.'),
        (t === 'hysteria2' || t === 'tuic') ? null : field('Отпечаток (uTLS)', sel(d, 'fingerprint', [['', 'нет'], 'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random']), 'Имитация TLS-отпечатка браузера. Для Reality обычно chrome.')) : null,
      tlsOn ? chk(d, 'insecure', 'Не проверять сертификат', 'Небезопасно: допускает подмену сервера. Включайте только для самоподписанных сертификатов.') : null,
      t === 'vless' ? chk(d, 'reality', 'Reality', 'Маскировка под чужой TLS-сайт без собственного сертификата. Требует публичный ключ и short id сервера.', { onchange: () => { if (d.reality) d.tls = true; rebuild(); } }) : null,
      (t === 'vless' && d.reality) ? fgrid(field('Public key', h('div', { class: 'pw' }, txt(d, 'public_key'), h('button', { type: 'button', class: 'btn sm', onclick: async () => {
        try { const r = await keygen('reality'); d.public_key = r.public; rebuild(); toast('Приватный ключ для сервера: ' + r.private, 'ok', 20000); } catch (e) { toastErr(e); }
      } }, 'создать пару')), 'Публичный ключ сервера Reality. Кнопка создаёт новую пару: публичный ключ подставится сюда, приватный будет показан для настройки сервера.'),
      field('Short ID', txt(d, 'short_id', { ph: 'hex до 16 символов' }))) : null));
  }
  if (['vless', 'vmess', 'trojan', 'shadowsocks', 'socks'].includes(t)) out.append(chk(d, 'udp', 'Разрешить UDP'));

  out.append(sec('Дополнительно', fgrid(
    field('Цепочка (detour)', sel(d, 'detour', [['', 'нет'], ...st.nodeNames().filter((n) => n !== d.name).map((n) => [n, n])]), 'Подключаться к этому узлу не напрямую, а через другой узел (двойной прокси).'),
    field('Привязка к интерфейсу', txt(d, 'bind_interface', { ph: 'например, eth3 или wan2', list: 'ifl' }), 'Выпустить трафик узла через конкретный WAN-интерфейс (мультиWAN).'))),
  chk(d, 'disabled', 'Узел выключен'));
  return out;
}
