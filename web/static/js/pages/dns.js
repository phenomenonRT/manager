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
    const flow = h('div', { class: 'dnsflow' });
    const sub = (title, role, ...rest) => h('div', { class: 'dnsblk' }, h('div', { class: 'dnsblk-h' }, h('b', title), h('span', { class: 'small mute' }, role)), ...rest);
    function drawFlow() {
      const via = d.remote_detour || S.settings.final;
      const way = (o) => (!o || o === 'direct') ? h('b', { class: 'bad' }, 'напрямую, мимо VPN') : h('b', o);
      const nRules = (d.rules || []).filter((r) => !r.disabled).length;
      const fin = d.final === 'local' ? 'local' : 'remote';
      clear(flow).append(
        h('div', { class: 'small mute', style: 'margin-bottom:4px' }, 'Как это работает сейчас'),
        h('ol', { class: 'dnsflow-l' },
          h('li', 'Устройство спрашивает адрес сайта → ядро принимает запрос на ', h('code', d.listen || '—')),
          nRules ? h('li', 'Если домен подходит под одно из ', h('b', nRules + ' DNS-правил'), ' — ответит тот сервер, который указан в правиле (local, remote или блок).') : null,
          h('li', 'Остальные домены → ', h('b', fin), ': ', h('code', (fin === 'remote' ? d.remote : d.local) || '—'), ', ходит ', fin === 'remote' ? way(via) : way(d.local_detour)),
          fin === 'remote' ? h('li', 'Сервер ', h('b', 'local'), ' (для правил и доменов, которые вы отправили на него): ', h('code', d.local || '—'), ', ходит ', way(d.local_detour)) : h('li', 'Сервер ', h('b', 'remote'), ' (для правил): ', h('code', d.remote || '—'), ', ходит ', way(via)),
          h('li', 'Имена самих серверов (DoH-сервера и VPN-узлов) ядро узнаёт через ', h('b', 'bootstrap'), ' ', h('code', d.bootstrap || d.local || '—'), ', всегда напрямую.'),
          d.mode === 'fakeip' ? h('li', 'Режим fakeip: приложению сразу выдаётся служебный адрес, настоящий ищется при соединении.') : null));
    }
    clear(body).append(
      enc && (via === 'direct' || !via) ? note('warn', 'Remote DNS (' + d.remote + ') сейчас ходит напрямую, мимо VPN: «Remote через» не задано, а Final = direct. DoH/DoT провайдеры в России нередко замедляют или режут — запросы будут идти секундами, а проверка узлов может не проходить. Выберите в «Remote через» вашу группу или назначьте её основной (Final).') : null,
      flow,
      fgrid(
        field('Слушать на', txt(d, 'listen', { ph: '127.0.0.1:1053' }), 'Адрес, где ядро принимает DNS-запросы. Чтобы перехватывать DNS из сети (dns_redirect) или подставить в dnsmasq для всей LAN, нужен 0.0.0.0:порт.'),
        field('Режим', sel(d, 'mode', [['normal', 'normal — обычный'], ['fakeip', 'fakeip — поддельные адреса']], { onchange: draw }), 'fakeip мгновенно отвечает адресом из служебной подсети и узнаёт домен при соединении. Ускоряет работу, но ломает приложения, которые хранят IP, и некоторые игры.'),
        field('DNS по умолчанию (final)', sel(d, 'final', [['remote', 'remote — основной'], ['local', 'local — локальный']]), 'Какой из двух серверов ниже отвечает на домены, не попавшие под DNS-правила.'),
        d.mode === 'fakeip' ? field('Диапазон fake-ip', txt(d, 'fakeip_range', { ph: '198.18.0.0/15' }), 'Служебная подсеть, не должна пересекаться с вашей LAN.') : null),
      h('div', { class: 'dnsblks' },
        sub('remote — основной', 'защищённый DNS, запросы идут через VPN',
          field('Сервер', dnsPick(d, 'remote', 'remote', { ph: 'https://1.1.1.1/dns-query', onchange: drawFlow }), 'Нажмите на поле — откроется список DoH/DoT/DoQ-серверов. Можно ввести свой: https://host/path, tls://host, quic://host, udp://host или просто IP.'),
          field('Через какой выход', sel(d, 'remote_detour', [['', 'по умолчанию (final)'], ...st.outbounds().filter((o) => o[0] !== 'block')]), 'Узел или группа, через которые запрос уходит к серверу. Пусто — как весь остальной трафик.')),
        sub('local — для своих', 'обычный DNS для российских и локальных доменов',
          field('Сервер', dnsPick(d, 'local', 'local', { ph: '77.88.8.8', onchange: drawFlow }), 'Выберите из списка, DNS роутера (local) или введите свой адрес.'),
          field('Через какой выход', sel(d, 'local_detour', [['', 'напрямую'], ...st.outbounds().filter((o) => o[0] !== 'block' && o[0] !== 'direct')]), 'Пусто — напрямую, мимо VPN. Имена самих узлов ядро всё равно разрешает напрямую.')),
        sub('bootstrap — служебный', 'только чтобы найти IP серверов выше',
          field('Сервер (только IP)', dnsPick(d, 'bootstrap', 'bootstrap', { ph: '77.88.8.8', onchange: drawFlow }), 'IP-адрес обычного DNS, которым ядро определяет адрес самого DoH/DoT-сервера и доменов VPN-узлов (иначе «курица и яйцо»). Всегда напрямую.'))),
      h('h3', 'DNS-правила'),
      h('p', { class: 'small mute' }, 'Позволяют отправить, например, домены .ru на local, а рекламу — заблокировать. Порядок важен: сверху вниз; всё, что не подошло, отвечает «DNS по умолчанию».'),
      h('div', { class: 'row', style: 'margin-bottom:10px' }, h('button', { class: 'btn primary', onclick: () => ed.add('geosite', 'local') }, '+ Добавить правило')),
      ed.el);
    drawFlow();
    body.oninput = body.onchange = () => drawFlow();
  }
  apd(root, pageHead('DNS', 'Разрешение имён внутри ядра'),
    h('div', { class: 'card' }, chk(d, 'enabled', 'Включить DNS ядра', 'Если выключено, ядро не перехватывает DNS клиентов, а доменные правила по DNS работают хуже.', { onchange: draw }), body));
  draw();
}
