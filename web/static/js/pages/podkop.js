import { apd, h, clear, pageHead, note, badge, toast, toastErr, confirmBox, copy } from '../ui.js';
import { get, post } from '../api.js';

export default async function (root) {
  const box = h('div');
  apd(root, pageHead('Podkop', 'Установка и управление Podkop — маршрутизацией на базе sing-box для OpenWrt'), box);
  let timer = 0, alive = true;

  async function act(name, confirmText) {
    if (confirmText && !(await confirmBox(confirmText, 'Продолжить', name === 'remove'))) return;
    try { await post('api/podkop/' + name); toast('Готово', 'ok'); } catch (e) { toastErr(e); }
    load();
  }

  const cmdRow = (title, cmd) => h('div', { style: 'margin:8px 0' },
    h('div', { class: 'small mute' }, title),
    h('div', { class: 'row' }, h('code', { class: 'mono grow', style: 'word-break:break-all' }, cmd),
      h('button', { class: 'btn', onclick: () => copy(cmd).then(() => toast('Скопировано', 'ok')) }, 'Копировать')));

  async function load() {
    clearTimeout(timer);
    let p;
    try { p = await get('api/podkop'); } catch (e) { clear(box).append(note('err', e.message)); return; }
    if (!alive) return;
    const kids = [];
    if (!p.supported) kids.push(note('warn', p.reason));
    else {
      kids.push(note('info', 'Podkop и ядро этой панели — альтернативы: оба перехватывают DNS и трафик и управляют sing-box. ' +
        'Одновременно запускать их нельзя, панель это блокирует. Настройка самого Podkop (разделы, списки, интерфейсы) делается в его собственном интерфейсе LuCI: Службы → Podkop.'));
      kids.push(h('div', { class: 'card' }, h('h2', 'Состояние'),
        h('dl', { class: 'kv' },
          h('dt', 'Установлен'), h('dd', p.installed ? badge('да', 'ok') : badge('нет', 'warn')),
          h('dt', 'Версия'), h('dd', p.version || '—'),
          h('dt', 'Служба'), h('dd', p.installed ? (p.running ? badge('работает', 'ok') : badge('остановлена')) : '—'),
          h('dt', 'Пакетный менеджер'), h('dd', p.pkg_manager || '—'),
          h('dt', 'Свободно на флеш'), h('dd', p.free_mb + ' МБ')),
        p.installed
          ? h('div', { class: 'row', style: 'flex-wrap:wrap;gap:8px;margin-top:10px' },
            h('button', { class: 'btn primary', disabled: p.job.running, onclick: () => act('start') }, 'Запустить'),
            h('button', { class: 'btn', disabled: p.job.running, onclick: () => act('restart') }, 'Перезапустить'),
            h('button', { class: 'btn', disabled: p.job.running, onclick: () => act('stop') }, 'Остановить'),
            h('button', { class: 'btn', disabled: p.job.running, onclick: () => act('enable') }, 'В автозапуск'),
            h('button', { class: 'btn', disabled: p.job.running, onclick: () => act('disable') }, 'Убрать из автозапуска'),
            h('button', { class: 'btn danger', disabled: p.job.running, onclick: () => act('remove', 'Остановить и удалить Podkop (пакеты podkop, luci-app-podkop, luci-i18n-podkop-ru)?') }, 'Удалить'))
          : h('div', { class: 'row', style: 'flex-wrap:wrap;gap:8px;margin-top:10px' },
            h('button', { class: 'btn primary', disabled: p.job.running, onclick: () => act('install', 'Скачать и запустить официальный установщик Podkop с GitHub (itdoginfo/podkop)? Он установит пакеты и зависимости (sing-box) и может удалить конфликтующие пакеты, например https-dns-proxy.') }, 'Установить'),
            h('button', { class: 'btn', disabled: p.job.running, onclick: () => act('install-mirror', 'Установить Podkop через зеркало mirror.podkop.net (если GitHub недоступен)?') }, 'Установить через зеркало'))));
      kids.push(h('div', { class: 'card' }, h('h2', 'Если установка из панели не проходит'),
        h('p', { class: 'small mute' }, 'Установщик Podkop может задавать вопросы — в панели ответить на них нельзя. Тогда выполните команду по SSH на роутере:'),
        cmdRow('С GitHub', p.install_cmd), cmdRow('Через зеркало', p.mirror_cmd),
        h('p', { class: 'small mute' }, 'Требования: OpenWrt 24.10 или 25.12, не менее 20 МБ свободной памяти (40 МБ, если sing-box ещё не установлен). Перед обновлением OpenWrt остановите Podkop.')));
      if (p.job && (p.job.running || p.job.finished)) {
        const pre = h('pre', { class: 'logbox mono', style: 'max-height:320px;overflow:auto;white-space:pre-wrap' }, (p.job.output || []).join('\n'));
        kids.push(h('div', { class: 'card' }, h('h2', p.job.title || 'Операция'),
          p.job.error ? note('err', p.job.error) : (p.job.finished ? note('ok', 'Завершено') : h('p', { class: 'mute' }, h('span', { class: 'spin' }), 'Выполняется…')), pre));
        setTimeout(() => { pre.scrollTop = pre.scrollHeight; }, 0);
      }
    }
    clear(box).append(...kids);
    if (p.job && p.job.running && alive) timer = setTimeout(load, 1500);
  }
  load();
  return () => { alive = false; clearTimeout(timer); };
}
