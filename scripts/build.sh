#!/bin/sh
# Кросс-сборка corepanel для роутеров. Результат — каталог dist/.
# Использование: scripts/build.sh [версия]
set -eu
cd "$(dirname "$0")/.."
VER="${1:-$(date +%Y.%m.%d)}"
mkdir -p dist
build() { # имя GOOS GOARCH [ENV...]
  name="$1"; os="$2"; arch="$3"; shift 3
  echo "==> $name"
  env CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" "$@" \
    go build -trimpath -ldflags "-s -w -X main.version=$VER" -o "dist/corepanel-$name" ./cmd/corepanel
}
build linux-amd64    linux amd64
build linux-arm64    linux arm64
build linux-armv7    linux arm   GOARM=7
build linux-armv5    linux arm   GOARM=5
build linux-mipsle   linux mipsle GOMIPS=softfloat   # Keenetic (MT7621 и др.), OpenWrt ramips
build linux-mips     linux mips   GOMIPS=softfloat   # OpenWrt ath79
build linux-mips64   linux mips64 GOMIPS64=softfloat
build linux-riscv64  linux riscv64
ls -l dist
