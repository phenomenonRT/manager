// Состояние туннелей AmneziaWG по журналу ядра. Ядро пишет события рукопожатия на уровне debug:
//   endpoint/awg[ТЕГ]: peer(…) - sending handshake initiation
//   endpoint/awg[ТЕГ]: peer(…) - handshake did not complete after 5 seconds, retrying (try N)
// Успех определяем по keepalive и ответу на рукопожатие: они появляются только при живой сессии.
const TAG = /endpoint\/awg\[([^\]]+)\]/;
const OK = /received handshake response|receiving keepalive|sending keepalive/i;
const INIT = /sending handshake initiation/i;
const FAIL = /handshake did not complete|retrying handshake/i;

// Возвращает { тег: { state: 'ok' | 'fail', tries } }; тегов без событий в результате нет.
export function parseAwgLog(lines) {
  const out = {};
  for (const raw of lines) {
    const line = String(raw);
    const m = TAG.exec(line);
    if (!m || !/peer\(/.test(line)) continue;
    const e = out[m[1]] || (out[m[1]] = { state: 'fail', tries: 0, init: 0 });
    if (OK.test(line)) { e.state = 'ok'; e.tries = 0; e.init = 0; }
    else if (FAIL.test(line)) { e.state = 'fail'; e.tries++; }
    else if (INIT.test(line)) { e.state = 'fail'; e.init++; }
  }
  return out;
}

// Цвет задержки: до 200 мс хорошо, 200–500 средне, дальше и сбой — плохо.
export function delayClass(d) {
  if (d === undefined || d === null) return '';
  if (d <= 0) return 'bad';
  if (d < 200) return 'good';
  if (d < 500) return 'warn';
  return 'slow';
}
