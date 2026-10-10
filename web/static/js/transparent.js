// Подсказка «трафик устройств не перехватывается»: без прозрачного прокси (redirect/tproxy/TUN)
// через ядро идут только приложения, вручную настроенные на порт mixed.
import { h, note, toast, toastErr } from './ui.js';
import * as st from './state.js';
import { get } from './api.js';

export const transparentOff = () => !!st.S.settings && st.S.settings.firewall.mode === 'off' && !st.S.settings.tun.enabled;

export function transparentNote() {
  if (!transparentOff()) return null;
  const s = st.S.settings;
  const plat = (st.S.system && st.S.system.platform) || {};
  const btn = h('button', { class: 'btn primary', onclick: async () => {
    btn.disabled = true;
    try {
      s.firewall.mode = 'redirect';
      if (!s.firewall.lan_ifaces.length) s.firewall.lan_ifaces = [plat.lan_iface || 'br-lan'];
      s.firewall.dns_redirect = true;
      // перехват DNS требует слушателя не на 127.0.0.1: берём адрес роутера в локальной сети
      const lan = s.firewall.lan_ifaces[0];
      let ip = '';
      try {
        const ifs = await get('api/interfaces');
        const i = (ifs || []).find((x) => x.name === lan);
        const a = i && (i.addrs || []).map((x) => String(x).split('/')[0]).find((x) => /^\d+\.\d+\.\d+\.\d+$/.test(x));
        if (a) ip = a;
      } catch (e) { /* возьмём 0.0.0.0 */ }
      const port = String(s.dns.listen || '').split(':').pop() || '1053';
      if (/^(127\.|localhost|\[?::1)/.test(String(s.dns.listen || '')) || !s.dns.listen) s.dns.listen = (ip || '0.0.0.0') + ':' + port;
      const r = await st.save(true);
      if (r.applied) el.remove();
      toast(r.applied ? 'Прозрачный прокси включён и применён' : 'Сохранено, но не применено: исправьте ошибки', r.applied ? 'ok' : 'err');
    } catch (e) { toastErr(e); }
    btn.disabled = false;
  } }, 'Включить для сети ' + (plat.lan_iface || 'br-lan'));
  const el = note('warn', h('b', 'Трафик устройств сети сейчас не идёт через ядро. '),
    'Прозрачный прокси выключен, поэтому правила действуют только для приложений, у которых вручную указан прокси роутера (порт ' + s.inbounds.mixed_port + '). ',
    'Кнопка включит режим redirect для TCP и перехват DNS; UDP и QUIC, а также другие режимы (tproxy, TUN) настраиваются в разделе «Входящие, TUN, сеть». ',
    h('div', { style: 'margin-top:8px' }, btn));
  return el;
}
