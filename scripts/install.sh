#!/bin/sh
# Установка corepanel на OpenWrt и Keenetic (Entware).
#   sh install.sh /путь/к/corepanel-linux-mipsle     — из локального файла
#   COREPANEL_BASE_URL=https://хост/каталог sh install.sh   — скачать corepanel-<arch> оттуда
set -eu

arch_key() {
  case "$(uname -m)" in
    x86_64|amd64) echo linux-amd64 ;;
    aarch64|arm64) echo linux-arm64 ;;
    armv7*|armv8l) echo linux-armv7 ;;
    armv6*|armv5*) echo linux-armv5 ;;
    mips64) echo linux-mips64 ;;
    mipsel) echo linux-mipsle ;;
    mips)
      # 1 на little-endian, 256 на big-endian
      if [ "$(printf '\001\000' | od -An -tu2 | tr -d ' ')" = 1 ]; then echo linux-mipsle; else echo linux-mips; fi ;;
    riscv64) echo linux-riscv64 ;;
    *) echo "unknown" ;;
  esac
}

if [ -x /bin/ndmc ] || [ -x /opt/bin/ndmc ] || [ -d /etc/ndm ] || [ -d /opt/etc/init.d ] && [ ! -f /etc/openwrt_release ]; then
  PLAT=keenetic; BIN=/opt/sbin/corepanel; INIT=/opt/etc/init.d/S99corepanel
elif [ -f /etc/openwrt_release ]; then
  PLAT=openwrt; BIN=/usr/bin/corepanel; INIT=/etc/init.d/corepanel
else
  echo "Не удалось определить систему (нужны OpenWrt или Keenetic с Entware)." >&2; exit 1
fi
echo "Система: $PLAT"
[ "$PLAT" = keenetic ] && [ ! -d /opt/etc/init.d ] && { echo "Установите Entware (компонент «Пакеты OPKG»)." >&2; exit 1; }

SRC="${1:-}"
if [ -z "$SRC" ]; then
  [ -n "${COREPANEL_BASE_URL:-}" ] || { echo "Укажите файл бинарника или COREPANEL_BASE_URL." >&2; exit 1; }
  K="$(arch_key)"; [ "$K" != unknown ] || { echo "Неизвестная архитектура: $(uname -m)" >&2; exit 1; }
  SRC=/tmp/corepanel.dl
  URL="${COREPANEL_BASE_URL%/}/corepanel-$K"
  echo "Скачиваю $URL"
  if command -v curl >/dev/null; then curl -fL -o "$SRC" "$URL"; else wget -O "$SRC" "$URL"; fi
fi

[ -x "$INIT" ] && "$INIT" stop 2>/dev/null || true
cp "$SRC" "$BIN"; chmod 755 "$BIN"
"$BIN" version >/dev/null || { echo "Бинарник не запускается — неверная архитектура?" >&2; exit 1; }

if [ "$PLAT" = openwrt ]; then
cat > "$INIT" <<'EOS'
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1
start_service() {
  procd_open_instance
  procd_set_param command /usr/bin/corepanel run
  procd_set_param respawn
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}
EOS
chmod 755 "$INIT"; "$INIT" enable
else
cat > "$INIT" <<'EOS'
#!/bin/sh
ENABLED=yes
PROCS=corepanel
ARGS="run"
PREARGS=""
DESC=$PROCS
PATH=/opt/sbin:/opt/bin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
case "$1" in
  start)   [ "$ENABLED" = yes ] || exit 0; (nohup /opt/sbin/corepanel $ARGS >/opt/var/log/corepanel.log 2>&1 &) ; echo "corepanel запущен" ;;
  stop)    killall corepanel 2>/dev/null; echo "corepanel остановлен" ;;
  restart) "$0" stop; sleep 1; "$0" start ;;
  *) echo "Использование: $0 {start|stop|restart}"; exit 1 ;;
esac
EOS
chmod 755 "$INIT"
fi

"$INIT" start
sleep 2
echo
echo "Готово. Панель: http://<адрес-роутера>:8088"
echo "Пароль первого входа: $( [ "$PLAT" = openwrt ] && logread 2>/dev/null | grep -o 'admin / [a-f0-9]*' | tail -1 || grep -o 'admin / [a-f0-9]*' /opt/var/log/corepanel.log 2>/dev/null | tail -1 )"
echo "Если пароль не виден: corepanel passwd"
