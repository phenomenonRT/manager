import { apd, h, clear, pageHead, note, field, fgrid, txt, num, pw, lines, sel, chk, badge, modal, copy, toastErr } from '../ui.js';
import { get } from '../api.js';
import * as st from '../state.js';

const S = st.S;
export default async function (root) {
  const s = S.settings, g = s.general, ib = s.inbounds, tun = s.tun, fw = s.firewall;
  const plat = (S.system && S.system.platform) || {};
  let ifs = [];
  try { ifs = (await get('api/interfaces')) || []; } catch (e) { /* список необязателен */ }
  const ifBox = h('div');
  function drawIfs() {
    const known = new Set(ifs.map((i) => i.name));
    const all = [...ifs, ...fw.lan_ifaces.filter((n) => !known.has(n)).map((n) => ({ name: n, up: false, addrs: [], missing: true }))];
    clear(ifBox).append(all.length ? h('div', { class: 'chips' }, all.map((i) => {
      const on = fw.lan_ifaces.includes(i.name);
      return h('label', { class: 'chip' + (on ? ' on' : '') }, h('input', { type: 'checkbox', checked: on, style: 'accent-color:var(--accent)', onchange: (e) => {
        fw.lan_ifaces = e.target.checked ? [...fw.lan_ifaces, i.name] : fw.lan_ifaces.filter((x) => x !== i.name); st.touch(); drawIfs();
      } }), i.name, h('small', (i.missing ? 'нет в системе' : (i.up ? 'up ' : 'down ') + ((i.addrs || [])[0] || ''))));
    })) : h('p', { class: 'small mute' }, 'Список интерфейсов недоступен — впишите имена вручную ниже.'));
  }
  const dl = h('datalist', { id: 'ifs' }, ifs.map((i) => h('option', { value: i.name })));
  const manual = { v: '' };

  async function preview() {
    try {
      const r = await get('api/firewall/preview');
      const pre = (t) => h('pre', { class: 'code', style: 'max-height:30vh' }, t || '(пусто)');
      modal({ title: 'Скрипты брандмауэра', wide: true, body: h('div',
        st.isDirty() ? note('warn', 'Есть несохранённые изменения — предпросмотр может не учитывать их.') : null,
        h('h3', 'Применение (up)'), pre(r.up), h('div', { class: 'row', style: 'margin:6px 0' }, h('button', { class: 'btn sm', onclick: () => copy(r.up || '') }, 'Копировать')),
        h('h3', 'Откат (down)'), pre(r.down), h('div', { class: 'row', style: 'margin:6px 0' }, h('button', { class: 'btn sm', onclick: () => copy(r.down || '') }, 'Копировать'))),
      buttons: [{ text: 'Закрыть', primary: true }] });
    } catch (e) { toastErr(e); }
  }

  apd(root, pageHead('Входящие, TUN и сеть', 'Как трафик попадает в ядро и общие параметры'), dl,
    (plat.notes && plat.notes.length) ? h('div', plat.notes.map((n) => note('warn', h('b', (plat.os_name || 'Платформа') + ': '), n))) : null,
    h('div', { class: 'card' }, h('h2', 'Какой режим выбрать'),
      h('div', { class: 'tw' }, h('table', h('thead', h('tr', h('th', 'Режим'), h('th', 'Как работает'), h('th', 'Когда подходит'))),
        h('tbody',
          h('tr', h('td', h('b', 'TUN')), h('td', 'Ядро создаёт виртуальный интерфейс и забирает через него маршрутизацию.'), h('td', 'Проще всего: ловит TCP, UDP и ICMP. Нужен модуль ядра ОС tun и (в sing-box) auto_redirect для nftables.')),
          h('tr', h('td', h('b', 'redirect')), h('td', 'Брандмауэр перенаправляет TCP-соединения LAN на порт ядра.'), h('td', 'Лёгкий, работает почти везде, но только TCP. UDP (игры, QUIC) идёт мимо.')),
          h('tr', h('td', h('b', 'tproxy')), h('td', 'Брандмауэр передаёт ядру TCP и UDP с сохранением адреса назначения.'), h('td', 'Полная поддержка UDP без TUN. Требует модулей tproxy/mark и правил маршрутизации.')))))),
    h('div', { class: 'cols' },
      h('div', { class: 'card' }, h('h2', 'Входящие порты'),
        field('Mixed (HTTP + SOCKS5)', num(ib, 'mixed_port', { min: 0, max: 65535 }), '0 — выключено. Можно указать как прокси в браузере или программе.'),
        field('Redirect', num(ib, 'redir_port', { min: 0, max: 65535 }), 'Порт для режима redirect (TCP).'),
        field('TProxy', num(ib, 'tproxy_port', { min: 0, max: 65535 }), 'Порт для режима tproxy (TCP+UDP).')),
      h('div', { class: 'card' }, h('h2', 'Общие'),
        fgrid(field('Уровень логов', sel(g, 'log_level', ['debug', 'info', 'warn', 'error'])),
          field('Контроллер (Clash API)', txt(g, 'controller', { ph: '127.0.0.1:9090' }), 'Адрес API ядра. Через него панель показывает трафик и переключает узлы.'),
          field('Секрет API', pw(g, 'secret'), 'Пароль доступа к API ядра. Если контроллер доступен из LAN — обязательно задайте.'),
          field('Каталог дашборда', txt(g, 'external_ui', { ph: '/opt/share/zashboard' }), 'Папка с веб-дашбордом (zashboard, metacubexd), он откроется на порту контроллера.'),
          field('Интерфейс по умолчанию', txt(g, 'default_interface', { ph: 'авто', list: 'ifs' }), 'Привязать исходящие соединения ядра к WAN-интерфейсу. Нужно при TUN, чтобы трафик ядра не зациклился.')),
        chk(g, 'allow_lan', 'Слушать в локальной сети (0.0.0.0)', 'Разрешает подключаться к портам ядра с других устройств LAN. Иначе доступно только самому роутеру.'),
        chk(g, 'ipv6', 'IPv6'), chk(g, 'tcp_fast_open', 'TCP Fast Open', 'Ускоряет установку соединений, но поддерживается не всеми серверами и ядрами ОС.'),
        chk(g, 'tcp_concurrent', 'Параллельные TCP-подключения', 'Пробует несколько адресов сервера одновременно (happy eyeballs).'))),
    h('div', { class: 'card' }, h('h2', 'TUN'),
      chk(tun, 'enabled', 'Включить TUN'),
      fgrid(field('Имя интерфейса', txt(tun, 'name', { ph: 'tun0' })), field('Адрес (CIDR)', txt(tun, 'address', { ph: '172.19.0.1/30' })),
        field('MTU', num(tun, 'mtu', { min: 576 })),
        field('Стек', sel(tun, 'stack', [['system', 'system — быстрее'], ['gvisor', 'gvisor — совместимее'], ['mixed', 'mixed — по умолчанию']]), 'system использует сетевой стек ОС, gvisor — собственный в пространстве пользователя (медленнее, но реже даёт проблемы). mixed: TCP через system, UDP через gvisor.')),
      fgrid(chk(tun, 'auto_route', 'auto_route', 'Ядро само настраивает маршруты, чтобы трафик шёл в TUN.'),
        chk(tun, 'strict_route', 'strict_route', 'Строгая маршрутизация: предотвращает утечки мимо TUN. Может мешать другим VPN.'),
        chk(tun, 'auto_redirect', 'auto_redirect (sing-box)', 'Использует nftables для перенаправления TCP — быстрее и экономнее по CPU. Нужен Linux с nftables.'),
        chk(tun, 'dns_hijack', 'Перехват DNS', 'Все DNS-запросы, попавшие в TUN, обрабатываются DNS ядра.')),
      field('Исключить подсети', lines(tun, 'exclude_cidr', { ph: '192.168.0.0/16' }), 'Подсети, которые не нужно направлять в TUN (по одной в строке).')),
    h('div', { class: 'card' }, h('h2', 'Прозрачный прокси (брандмауэр)'),
      fgrid(field('Режим', sel(fw, 'mode', [['off', 'off — выключен'], ['redirect', 'redirect — TCP'], ['tproxy', 'tproxy — TCP+UDP']]), 'Чем перехватывать трафик LAN. При использовании TUN обычно оставляют off.'),
        field('Бэкенд', sel(fw, 'backend', [['auto', 'auto'], ['nft', 'nftables'], ['iptables', 'iptables']]), 'auto — по возможностям системы (' + (plat.firewall_backend || 'не определено') + ').'),
        field('fwmark', num(fw, 'fwmark', { min: 1 }), 'Метка пакетов в режиме tproxy.'),
        field('Таблица маршрутизации', num(fw, 'route_table', { min: 1 }), 'Номер таблицы ip route для tproxy.')),
      h('div', { class: 'lbl small mute' }, 'LAN-интерфейсы (входящие, трафик с которых перехватывается)'), ifBox,
      h('div', { class: 'row', style: 'margin:8px 0 12px' }, h('input', { type: 'text', style: 'max-width:200px', 'aria-label': 'Добавить интерфейс', placeholder: plat.lan_iface || 'br-lan', list: 'ifs', oninput: (e) => { manual.v = e.target.value.trim(); } }),
        h('button', { class: 'btn sm', onclick: (e) => { if (manual.v && !fw.lan_ifaces.includes(manual.v)) { fw.lan_ifaces.push(manual.v); st.touch(); drawIfs(); e.target.previousSibling.value = ''; manual.v = ''; } } }, 'Добавить')),
      fgrid(field('Проксировать только эти IP/подсети', lines(fw, 'include', { ph: '192.168.1.50\n192.168.1.64/28' }), 'Если список не пуст — прокси работает только для этих устройств.'),
        field('Не проксировать эти IP/подсети', lines(fw, 'exclude', { ph: '192.168.1.10' }), 'Устройства LAN, которые идут напрямую (например, ТВ-приставка).'),
        field('Адреса назначения в обход', lines(fw, 'bypass_dst', { ph: '203.0.113.0/24' }), 'Эти адреса всегда идут напрямую, минуя прокси.')),
      chk(fw, 'dns_redirect', 'Перехватывать DNS (порт 53) на ядро', 'Устройства, у которых прописан чужой DNS, всё равно будут использовать DNS ядра. Требует DNS-слушатель на 0.0.0.0.'),
      h('div', { class: 'row' }, h('button', { class: 'btn', onclick: preview }, 'Показать скрипты nft/iptables'), h('span', { class: 'small mute' }, 'Проверьте, что будет выполнено при старте'))));
  drawIfs();
}
