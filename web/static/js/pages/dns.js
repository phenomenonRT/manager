import { apd, h, clear, pageHead, note, field, fgrid, txt, sel, chk } from '../ui.js';
import { ruleEditor } from '../rules.js';
import * as st from '../state.js';

const S = st.S;
export default async function (root) {
  const d = S.settings.dns;
  const ed = ruleEditor({ rules: d.rules, dns: true, outs: [['remote', 'remote — основной (через прокси)'], ['local', 'local — локальный/провайдера'], ['block', 'block — не отвечать']], defaultOut: 'local' });
  const body = h('div');
  function draw() {
    if (!d.enabled) { clear(body).append(note('', 'DNS ядра выключен: используется системный DNS.')); return; }
    clear(body).append(
      note('', 'Схема: «remote» — защищённый DNS (DoH/DoT), запросы идут через прокси; «local» — обычный DNS провайдера или Яндекса, для российских и локальных доменов.'),
      fgrid(
        field('Слушать на', txt(d, 'listen', { ph: '127.0.0.1:1053' }), 'Адрес, где ядро принимает DNS-запросы. Чтобы перехватывать DNS из сети (dns_redirect) или подставить в dnsmasq для всей LAN, нужен 0.0.0.0:порт.'),
        field('Режим', sel(d, 'mode', [['normal', 'normal — обычный'], ['fakeip', 'fakeip — поддельные адреса']], { onchange: draw }), 'fakeip мгновенно отвечает адресом из служебной подсети и узнаёт домен при соединении. Ускоряет работу, но ломает приложения, которые хранят IP, и некоторые игры.'),
        field('Remote DNS', txt(d, 'remote', { ph: 'https://1.1.1.1/dns-query' }), 'Формат: https://host/path, tls://host, quic://host, udp://host или просто IP.'),
        field('Local DNS', txt(d, 'local', { ph: '77.88.8.8' })),
        field('Bootstrap DNS', txt(d, 'bootstrap', { ph: '77.88.8.8' }), 'IP-адрес обычного DNS, которым ядро определяет адрес самого DoH/DoT-сервера (иначе «курица и яйцо»).'),
        field('Remote через', sel(d, 'remote_detour', [['', 'по умолчанию (final)'], ...st.outbounds().filter((o) => o[0] !== 'block')]), 'Через какой узел или группу ходить к Remote DNS. Пусто — как весь остальной трафик.'),
        d.mode === 'fakeip' ? field('Диапазон fake-ip', txt(d, 'fakeip_range', { ph: '198.18.0.0/15' }), 'Служебная подсеть, не должна пересекаться с вашей LAN.') : null,
        field('DNS по умолчанию (final)', sel(d, 'final', [['remote', 'remote'], ['local', 'local']]), 'Какой сервер отвечает на домены, не попавшие под DNS-правила.')),
      h('h3', 'DNS-правила'),
      h('p', { class: 'small mute' }, 'Позволяют отправить, например, домены .ru на local, а рекламу — заблокировать. Порядок важен: сверху вниз.'),
      h('div', { class: 'row', style: 'margin-bottom:10px' }, h('button', { class: 'btn primary', onclick: () => ed.add('geosite', 'local') }, '+ Добавить правило')),
      ed.el);
  }
  apd(root, pageHead('DNS', 'Разрешение имён внутри ядра'),
    h('div', { class: 'card' }, chk(d, 'enabled', 'Включить DNS ядра', 'Если выключено, ядро использует системный DNS, а доменные правила работают хуже.', { onchange: draw }), body));
  draw();
}
