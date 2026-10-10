// Глобальное состояние: редактируемые настройки, статус, список замечаний.
import { get, put, post } from './api.js';

export const S = { settings: null, saved: '', system: null, status: null, session: null, issues: [], needApply: false, busy: false };
const subs = new Set();
export const subscribe = (f) => { subs.add(f); return () => subs.delete(f); };
export const emit = () => subs.forEach((f) => f());
export const touch = emit;
export const isDirty = () => !!S.settings && JSON.stringify(S.settings) !== S.saved;

export function normalize(s) {
  const arr = (o, k) => { if (!Array.isArray(o[k])) o[k] = []; };
  for (const k of ['general', 'inbounds', 'tun', 'dns', 'firewall', 'download']) if (!s[k] || typeof s[k] !== 'object') s[k] = {};
  for (const k of ['nodes', 'groups', 'rule_sets', 'rules']) arr(s, k);
  arr(s.dns, 'rules'); arr(s.tun, 'exclude_cidr');
  for (const k of ['lan_ifaces', 'include', 'exclude', 'bypass_dst']) arr(s.firewall, k);
  if (!s.core) s.core = 'singbox';
  if (!s.final) s.final = 'direct';
  for (const g of s.groups) arr(g, 'members');
  return s;
}
// Заполняет пропущенные поля значениями по умолчанию (для импорта файла).
export function fill(t, d) {
  for (const k of Object.keys(d)) {
    if (t[k] === undefined || t[k] === null) t[k] = d[k];
    else if (d[k] && typeof d[k] === 'object' && !Array.isArray(d[k]) && typeof t[k] === 'object') fill(t[k], d[k]);
  }
  return t;
}

export async function loadSettings() {
  const r = await get('api/settings');
  S.settings = normalize((r && r.settings) || r);
  S.saved = JSON.stringify(S.settings);
  emit();
}
export async function loadSystem() { S.system = await get('api/system'); emit(); return S.system; }
export async function loadStatus() { S.status = await get('api/status'); emit(); return S.status; }
export const CORE_NAME = { singbox: 'sing-box', mihomo: 'Mihomo', amnezia: 'amnezia-box' };
export const coreName = (c) => CORE_NAME[c] || c || '';
// sing-box и его форк amnezia-box читают один и тот же формат конфига.
export const isSb = (c) => c === 'singbox' || c === 'amnezia';
export const isRunning = () => !!S.status && (S.status.state === 'running' || S.status.state === 'starting');

export async function validate() {
  const r = await post('api/validate', S.settings);
  S.issues = (r && r.issues) || [];
  emit();
  return S.issues;
}
export const hasErrors = () => S.issues.some((i) => i.level === 'error');

// Возвращает {saved, applied}. Бросает исключение при ошибке сети/сервера.
export async function save(apply) {
  S.busy = true; emit();
  try {
    pruneRefs();
    await fixDnsListen();
    await validate();
    const r = await put('api/settings', S.settings);
    if (r && r.issues && r.issues.length) S.issues = r.issues;
    S.saved = JSON.stringify(S.settings);
    S.needApply = true;
    let applied = false;
    if (apply && !hasErrors()) {
      await loadStatus().catch(() => {});
      await post(isRunning() ? 'api/service/restart' : 'api/service/start');
      S.needApply = false; applied = true;
      await loadStatus().catch(() => {});
    }
    return { saved: true, applied };
  } finally { S.busy = false; emit(); }
}
export function revert() {
  S.settings = normalize(JSON.parse(S.saved));
  S.issues = [];
  emit();
}

// Все возможные исходящие: [значение, подпись]
export function outbounds(opts = {}) {
  const s = S.settings;
  const out = [];
  for (const g of s.groups) out.push([g.name, 'группа: ' + g.name]);
  for (const n of s.nodes) out.push([n.name, 'узел: ' + n.name]);
  out.push(['direct', 'direct — напрямую'], ['block', 'block — блокировать']);
  return opts.noGroups ? out.filter((x) => !x[1].startsWith('группа')) : out;
}
export const nodeNames = () => S.settings.nodes.map((n) => n.name);

// Переименование узла/группы с обновлением всех ссылок.
export function renameRef(oldN, newN) {
  if (!oldN || oldN === newN) return;
  const s = S.settings;
  for (const g of s.groups) g.members = g.members.map((m) => (m === oldN ? newN : m));
  for (const n of s.nodes) if (n.detour === oldN) n.detour = newN;
  for (const r of s.rules) if (r.outbound === oldN) r.outbound = newN;
  if (s.final === oldN) s.final = newN;
  if (s.general.update_via === oldN) s.general.update_via = newN;
  if (s.dns.remote_detour === oldN) s.dns.remote_detour = newN;
}
// Перехват DNS брандмауэром не работает при слушателе на 127.0.0.1: переносим его на адрес роутера в LAN.
export async function fixDnsListen() {
  const s = S.settings;
  if (!s || !s.firewall.dns_redirect || !s.dns.enabled) return false;
  const cur = String(s.dns.listen || '');
  if (cur && !/^(127\.|localhost|\[?::1)/.test(cur)) return false;
  const lan = s.firewall.lan_ifaces[0] || (S.system && S.system.platform && S.system.platform.lan_iface) || 'br-lan';
  let ip = '';
  try {
    const ifs = await get('api/interfaces');
    const i = (ifs || []).find((x) => x.name === lan);
    ip = ((i && i.addrs) || []).map((x) => String(x).split('/')[0]).find((x) => /^\d+\.\d+\.\d+\.\d+$/.test(x)) || '';
  } catch (e) { /* возьмём 0.0.0.0 */ }
  const port = cur.split(':').pop() || '1053';
  s.dns.listen = (ip || '0.0.0.0') + ':' + (/^\d+$/.test(port) ? port : '1053');
  window.dispatchEvent(new CustomEvent('cp-fixed', { detail: ['DNS-слушатель перенесён на ' + s.dns.listen + ' (нужно для перехвата DNS)'] }));
  return true;
}

// Убирает ссылки на несуществующие узлы и группы (после удаления или замены узлов).
// Битые ссылки заменяются на direct, группы теряют лишних участников. Возвращает список правок.
export function pruneRefs() {
  const s = S.settings, out = [];
  const have = new Set(['direct', 'block']);
  for (const n of s.nodes) have.add(n.name);
  for (const g of s.groups) have.add(g.name);
  for (const g of s.groups) {
    const keep = g.members.filter((m) => have.has(m));
    if (keep.length !== g.members.length) { out.push('группа «' + g.name + '»: убраны несуществующие участники'); g.members = keep; }
  }
  for (const n of s.nodes) if (n.detour && !have.has(n.detour)) { out.push('узел «' + n.name + '»: сброшена цепочка'); n.detour = ''; }
  if (!have.has(s.final)) { out.push('исходящий по умолчанию «' + s.final + '» → direct'); s.final = 'direct'; }
  s.rules.forEach((r, i) => { if (r.outbound && !have.has(r.outbound)) { out.push('правило №' + (i + 1) + ': «' + r.outbound + '» → direct'); r.outbound = 'direct'; } });
  if (s.general.update_via && !have.has(s.general.update_via)) { out.push('загрузка наборов правил: сброшен прокси'); s.general.update_via = ''; }
  if (s.dns.remote_detour && !have.has(s.dns.remote_detour)) { out.push('DNS remote: сброшен «Remote через»'); s.dns.remote_detour = ''; }
  if (out.length) window.dispatchEvent(new CustomEvent('cp-fixed', { detail: out }));
  return out;
}
export function uniqueName(name, taken) {
  if (!taken.has(name)) return name;
  let i = 2;
  while (taken.has(name + ' ' + i)) i++;
  return name + ' ' + i;
}
