// Поле DNS-адреса с выпадающим списком: готовые DoH/DoT/DoQ-серверы, обычные DNS и DNS роутера.
// Список только подсказывает — вводить можно любой адрес вручную.
import { h, fire } from './ui.js';
import { get } from './api.js';

const DOH = [
  ['Cloudflare', 'https://1.1.1.1/dns-query'],
  ['Google', 'https://dns.google/dns-query'],
  ['Quad9', 'https://dns.quad9.net/dns-query'],
  ['AdGuard', 'https://dns.adguard-dns.com/dns-query'],
  ['Яндекс', 'https://common.dns.yandex.net/dns-query'],
  ['NextDNS', 'https://dns.nextdns.io/dns-query'],
  ['Mullvad', 'https://dns.mullvad.net/dns-query'],
  ['OpenDNS', 'https://doh.opendns.com/dns-query'],
  ['DNS.SB', 'https://doh.dns.sb/dns-query'],
];
const DOT = [
  ['Cloudflare', 'tls://1.1.1.1'],
  ['Google', 'tls://8.8.8.8'],
  ['Quad9', 'tls://9.9.9.9'],
  ['AdGuard', 'tls://dns.adguard-dns.com'],
  ['Яндекс', 'tls://common.dns.yandex.net'],
  ['NextDNS', 'tls://dns.nextdns.io'],
  ['Mullvad', 'tls://dns.mullvad.net'],
];
const DOQ = [
  ['AdGuard', 'quic://dns.adguard-dns.com'],
  ['NextDNS', 'quic://dns.nextdns.io'],
];
const PLAIN = [
  ['Яндекс', '77.88.8.8'],
  ['Яндекс (резерв)', '77.88.8.1'],
  ['Cloudflare', '1.1.1.1'],
  ['Google', '8.8.8.8'],
  ['Quad9', '9.9.9.9'],
  ['AdGuard', '94.140.14.14'],
  ['OpenDNS', '208.67.222.222'],
];

const G = {
  doh: { title: 'DoH — DNS поверх HTTPS', tag: 'DoH', items: DOH },
  dot: { title: 'DoT — DNS поверх TLS', tag: 'DoT', items: DOT },
  doq: { title: 'DoQ — DNS поверх QUIC', tag: 'DoQ', items: DOQ },
  plain: { title: 'Обычный DNS (UDP)', tag: 'UDP', items: PLAIN },
};
// какие группы показывать в каком поле
const KINDS = {
  remote: ['doh', 'dot', 'doq', 'plain'],
  local: ['plain', 'doh', 'dot'],
  bootstrap: ['plain'],
};

let sysP = null;
// Адреса DNS, которые роутер получил от провайдера (читаются на роутере). Ошибка — просто пустой список.
export function loadSystemDNS(force) {
  if (!sysP || force) sysP = get('api/dns/system').then((r) => (Array.isArray(r) ? r : [])).catch(() => []);
  return sysP;
}

const IP4 = /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/;
const IP6 = /^(\[[0-9a-f:.]+\](:\d+)?|[0-9a-f:]*:[0-9a-f:.]*)$/i;
const HOST = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\d+)?$/i;
const isIP = (v) => IP4.test(v) || IP6.test(v);

// Что за адрес ввели: подпись + предупреждение, если ядро его не поймёт или он не подходит полю.
export function describe(v, kind) {
  v = (v || '').trim();
  if (!v) return null;
  if (v === 'local') return { text: 'local — системный резолвер роутера', ok: true };
  const m = /^([a-z0-9]+):\/\/(.*)$/i.exec(v);
  let scheme = 'udp', rest = v;
  if (m) { scheme = m[1].toLowerCase(); rest = m[2]; }
  const names = { udp: 'обычный DNS (UDP)', tcp: 'обычный DNS (TCP)', tls: 'DoT — DNS поверх TLS', quic: 'DoQ — DNS поверх QUIC', https: 'DoH — DNS поверх HTTPS', h3: 'DoH поверх HTTP/3' };
  if (!names[scheme]) return { text: 'Схема «' + scheme + '://» не поддерживается. Допустимы: https, tls, quic, h3, udp, tcp.', ok: false };
  const host = rest.split('/')[0];
  if (!host || !(isIP(host) || HOST.test(host))) return { text: 'Не похоже на адрес сервера: «' + host + '».', ok: false };
  const encrypted = scheme === 'tls' || scheme === 'quic' || scheme === 'https' || scheme === 'h3';
  if (kind === 'bootstrap') {
    if (encrypted || !isIP(host)) return { text: 'Для Bootstrap нужен обычный IP-адрес (например 77.88.8.8): им ядро находит адрес самого DoH/DoT-сервера.', ok: false };
    return { text: names[scheme], ok: true };
  }
  let t = names[scheme];
  if (!isIP(host)) t += '; адрес «' + host + '» ядро найдёт через Bootstrap DNS';
  if ((scheme === 'https' || scheme === 'h3') && !rest.includes('/')) t += '; путь не указан, будет /dns-query';
  return { text: t, ok: true };
}

// obj[key] — редактируемое значение. kind: remote | local | bootstrap.
export function dnsPick(obj, key, kind, o = {}) {
  const uid = 'dp' + Math.random().toString(36).slice(2, 8);
  let sys = [];
  let open = false, typed = false, act = -1, rows = [];
  const input = h('input', {
    type: 'text', value: obj[key] ?? '', placeholder: o.ph, autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off',
    role: 'combobox', 'aria-autocomplete': 'list', 'aria-expanded': 'false', 'aria-controls': uid,
    oninput: (e) => { obj[key] = e.target.value; typed = true; act = -1; show(); drawHint(); fire(o); },
    onfocus: () => { typed = false; act = -1; show(); },
    onclick: () => { if (!open) { typed = false; show(); } },
    onkeydown: (e) => {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        if (!open) { typed = false; show(); return; }
        if (!rows.length) return;
        act = (act + (e.key === 'ArrowDown' ? 1 : -1) + rows.length) % rows.length;
        mark();
      } else if (e.key === 'Enter') {
        if (open && act >= 0 && rows[act]) { e.preventDefault(); pick(rows[act].addr); }
      } else if (e.key === 'Escape') {
        if (open) { e.preventDefault(); e.stopPropagation(); hide(); }
      } else if (e.key === 'Tab') hide();
    },
    onblur: () => hide(),
  });
  const list = h('div', { class: 'dp-list', id: uid, role: 'listbox', hidden: true });
  const hint = h('div', { class: 'dp-hint small', 'aria-live': 'polite' });
  const toggle = h('button', {
    type: 'button', class: 'dp-btn', tabindex: '-1', 'aria-label': 'Показать список серверов', title: 'Список серверов',
    onmousedown: (e) => e.preventDefault(),
    onclick: (e) => { e.preventDefault(); if (open) hide(); else { input.focus(); typed = false; show(); } },
  }, '▾');
  const wrap = h('div', { class: 'dp' }, h('div', { class: 'dp-in' }, input, toggle), list, hint);

  function groups() {
    const gs = KINDS[kind].map((k) => ({ title: G[k].title, items: G[k].items.map(([n, a]) => ({ name: n, addr: a, tag: G[k].tag })) }));
    const sysItems = sys.map((s) => ({ name: s.source, addr: s.addr, tag: 'роутер' }));
    if (kind === 'local') gs.unshift({ title: 'Роутер', items: [{ name: 'DNS роутера', addr: 'local', tag: 'local' }, ...sysItems] });
    else if (sysItems.length) gs.splice(kind === 'bootstrap' ? 0 : gs.length, 0, { title: 'Получены роутером от провайдера', items: sysItems });
    return gs;
  }
  function show() {
    const q = typed ? input.value.trim().toLowerCase() : '';
    const cur = (obj[key] ?? '').trim();
    rows = [];
    list.replaceChildren();
    for (const g of groups()) {
      const its = g.items.filter((i) => !q || i.addr.toLowerCase().includes(q) || i.name.toLowerCase().includes(q));
      if (!its.length) continue;
      list.append(h('div', { class: 'dp-g' }, g.title));
      for (const i of its) {
        const idx = rows.length;
        rows.push(i);
        list.append(h('div', {
          class: 'dp-o' + (i.addr === cur ? ' cur' : ''), role: 'option', id: uid + '-' + idx, 'aria-selected': i.addr === cur ? 'true' : 'false',
          onmousedown: (e) => e.preventDefault(),
          onclick: (e) => { e.preventDefault(); e.stopPropagation(); pick(i.addr); },
          onmousemove: () => { if (act !== idx) { act = idx; mark(); } },
        }, h('span', { class: 'dp-t' }, i.tag), h('span', { class: 'dp-n' }, i.name), h('code', { class: 'dp-a' }, i.addr)));
      }
    }
    if (!rows.length) list.append(h('div', { class: 'dp-empty small' }, 'Нет совпадений — будет использован адрес, который вы ввели.'));
    else if (typed && q) list.append(h('div', { class: 'dp-empty small' }, 'Можно оставить свой адрес — список только подсказывает.'));
    open = true; list.hidden = false; input.setAttribute('aria-expanded', 'true');
    mark(false);
  }
  function mark(scroll = true) {
    list.querySelectorAll('.dp-o').forEach((el, i) => el.classList.toggle('act', i === act));
    if (act >= 0) {
      input.setAttribute('aria-activedescendant', uid + '-' + act);
      const el = list.children && document.getElementById(uid + '-' + act);
      if (scroll && el) el.scrollIntoView({ block: 'nearest' });
    } else input.removeAttribute('aria-activedescendant');
  }
  function hide() { open = false; list.hidden = true; input.setAttribute('aria-expanded', 'false'); input.removeAttribute('aria-activedescendant'); }
  function pick(addr) {
    obj[key] = addr; input.value = addr; typed = false;
    hide(); drawHint(); fire(o);
  }
  function drawHint() {
    const d = describe(obj[key], kind);
    hint.className = 'dp-hint small' + (d ? (d.ok ? ' ok' : ' bad') : '');
    hint.textContent = d ? d.text : '';
  }
  drawHint();
  loadSystemDNS().then((r) => { sys = r; if (open) show(); });
  return wrap;
}
