#!/bin/sh
# Сборка .ipk из бинарников dist/. Использование: scripts/mkipk.sh [версия]
# Результат: dist/ipk/corepanel_<версия>_<арх>_<openwrt|entware>.ipk
set -eu
cd "$(dirname "$0")/.."
VER="${1:-0.1.0}"
OUT="$PWD/dist/ipk"; mkdir -p "$OUT"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

mk() { # вариант архитектура бинарник
  var="$1"; arch="$2"; bin="dist/corepanel-linux-$arch"
  [ -f "$bin" ] || { echo "нет $bin" >&2; return; }
  w="$T/$var-$arch"; mkdir -p "$w/data" "$w/control"
  if [ "$var" = openwrt ]; then
    install -D -m 755 "$bin" "$w/data/usr/bin/corepanel"
    install -D -m 755 scripts/ipk/openwrt.init "$w/data/etc/init.d/corepanel"
    cat > "$w/control/postinst" <<'EOS'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
/etc/init.d/corepanel enable
/etc/init.d/corepanel start 2>/dev/null
echo "corepanel запущен: http://<адрес-роутера>:8088 (вход без пароля из локальной сети; включить пароль root — раздел «Система»)"
exit 0
EOS
    cat > "$w/control/prerm" <<'EOS'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
/etc/init.d/corepanel stop 2>/dev/null
/etc/init.d/corepanel disable 2>/dev/null
exit 0
EOS
  else
    install -D -m 755 "$bin" "$w/data/opt/sbin/corepanel"
    install -D -m 755 scripts/ipk/entware.init "$w/data/opt/etc/init.d/S99corepanel"
    cat > "$w/control/postinst" <<'EOS'
#!/bin/sh
/opt/etc/init.d/S99corepanel restart
echo "corepanel запущен: http://<адрес-роутера>:8088 (вход без пароля из локальной сети; включить пароль root — раздел «Система»)"
exit 0
EOS
    cat > "$w/control/prerm" <<'EOS'
#!/bin/sh
/opt/etc/init.d/S99corepanel stop 2>/dev/null
exit 0
EOS
  fi
  chmod 755 "$w/control/postinst" "$w/control/prerm"
  size=$(du -sk "$w/data" | cut -f1); size=$((size*1024))
  cat > "$w/control/control" <<EOS
Package: corepanel
Version: $VER
Depends: libc
Source: corepanel
Section: net
Priority: optional
Maintainer: corepanel
Architecture: all
Installed-Size: $size
Description: Web panel for sing-box and Mihomo (binary for $arch)
EOS
  # libc нужен только как формальность для opkg; на статическом бинарнике не влияет
  sed -i '/^Depends:/d' "$w/control/control"
  TAR="tar --owner=0 --group=0 --numeric-owner --format=gnu"
  ( cd "$w/control" && $TAR -czf ../control.tar.gz ./control ./postinst ./prerm )
  ( cd "$w/data"    && $TAR -czf ../data.tar.gz . )
  echo "2.0" > "$w/debian-binary"
  f="$OUT/corepanel_${VER}_${arch}_${var}.ipk"
  ( cd "$w" && $TAR -czf "$f" ./debian-binary ./data.tar.gz ./control.tar.gz )
  echo "==> $f"
}
for a in mipsle mips mips64 armv7 armv5 arm64 amd64 riscv64; do
  mk openwrt "$a"; mk entware "$a"
done
