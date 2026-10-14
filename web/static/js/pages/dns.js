import { apd, h, clear, pageHead, note, field, fgrid, txt, sel, chk } from '../ui.js';
import { ruleEditor } from '../rules.js';
import { dnsPick } from '../dnspick.js';
import * as st from '../state.js';

const S = st.S;
export default async function (root) {
  const d = S.settings.dns;
  const ed = ruleEditor({ rules: d.rules, dns: true, outs: [['remote', 'remote — основной (через прокси)'], ['local', 'local — локальный/провайдера'], ['block', 'block — не отвечать']], defaultOut: 'local' });
  const body = h('div');
  function draw() {
    if (!d.enabled) { clear(body).append(note('', 'DNS ядра выключен: клиентские DNS-запросы ядро не перехватывает и идут по обычным правилам. Сами имена (проверка задержки, наборы правил) ядро разрешает напрямую через адрес «Bootstrap»; включите DNS ядра, если нужны доменные правила, DoH/DoT и проведение DNS через VPN («Remote через», «Local через»). Запросы клиентов при выключенном DNS идут по обычным правилам — то есть в VPN, если он выбран по умолчанию (Final).')); return; }
    const via = d.remote_detour || S.settings.final;
    const enc = /^(https|tls|quic|h3):\/\//i.test((d.remote || '').trim());
    clear(body).append(
      enc && (via === 'direct' || !via) ? note('warn', 'Remote DNS (' + d.remote + ') сейчас ходит напрямую, мимо VPN: «Remote через» не задано, а Final = direct. DoH/DoT провайдеры в России нередко замедляют или режут — запросы будут идти секундами, а проверка узлов может не проходить. Выберите в «Remote через» вашу группу или назначьте её основной (Final).') : null,
      note('', 'Схема: «remote» — защищённый DNS (DoH/DoT), запросы идут через прокси; «local» — обычный DNS провайдера или Яндекса, для российских и локальных доменов.'),
      fgrid(
        field('Слушать на', txt(d, 'listen', { ph: '127.0.0.1:1053' }), 'Адрес, где ядро принимает DNS-запросы. Чтобы перехватывать DNS из сети (dns_redirect) или подставить в dnsmasq для всей LAN, нужен 0.0.0.0:порт.'),
        field('Режим', sel(d, 'mode', [['normal', 'normal — обычный'], ['fakeip', 'fakeip — поддельные адреса']], { onchange: draw }), 'fakeip мгновенно отвечает адресом из служебной подсети и узнаёт домен при соединении. Ускоряет работу, но ломает приложения, которые хранят IP, и некоторые игры.'),
        field('Remote DNS', dnsPick(d, 'remote', 'remote', { ph: 'https://1.1.1.1/dns-query' }), 'Нажмите на поле — откроется список DoH/DoT/DoQ-серверов. Можно ввести свой: https://host/path, tls://host, quic://host, udp://host или просто IP.'),
        field('Local DNS', dnsPick(d, 'local', 'local', { ph: '77.88.8.8' }), 'Обычный DNS для российских и локальных доменов. Выберите из списка, DNS роутера (local) или введите свой адрес.'),
        field('Bootstrap DNS', dnsPick(d, 'bootstrap', 'bootstrap', { ph: '77.88.8.8' }), 'IP-адрес обычного DNS, которым ядро определяет адрес самого DoH/DoT-сервера (иначе «курица и яйцо»).'),
        field('Remote через', sel(d, 'remote_detour', [['', 'по умолчанию (final)'], ...st.outbounds().filter((o) => o[0] !== 'block')]), 'Через какой узел или группу ходить к Remote DNS. Пусто — как весь остальной трафик.'),
        field('Local через', sel(d, 'local_detour', [['', 'напрямую'], ...st.outbounds().filter((o) => o[0] !== 'block' && o[0] !== 'direct')]), 'Через какой узел или группу ходить к Local DNS. Пусто — напрямую, мимо VPN. Имена самих узлов ядро всё равно разрешает напрямую.'),
        d.mode === 'fakeip' ? field('Диапазон fake-ip', txt(d, 'fakeip_range', { ph: '198.18.0.0/15' }), 'Служебная подсеть, не должна пересекаться с вашей LAN.') : null,
        field('DNS по умолчанию (final)', sel(d, 'final', [['remote', 'remote'], ['local', 'local']]), 'Какой сервер отвечает на домены, не попавшие под DNS-правила.')),
      h('h3', 'DNS-правила'),
      h('p', { class: 'small mute' }, 'Позволяют отправить, например, домены .ru на local, а рекламу — заблокировать. Порядок важен: сверху вниз.'),
      h('div', { class: 'row', style: 'margin-bottom:10px' }, h('button', { class: 'btn primary', onclick: () => ed.add('geosite', 'local') }, '+ Добавить правило')),
      ed.el);
  }
  apd(root, pageHead('DNS', 'Разрешение имён внутри ядра'),
    h('div', { class: 'card' }, chk(d, 'enabled', 'Включить DNS ядра', 'Если выключено, ядро не перехватывает DNS клиентов, а доменные правила по DNS работают хуже.', { onchange: draw }), body));
  draw();
}
