# corepanel — панель настройки sing-box и Mihomo для роутеров

Веб-интерфейс (Go + JS + CSS, один статический бинарник ~8 МБ, без зависимостей) для **OpenWrt** и **Keenetic (Entware)**.
Позволяет выбрать и установить ядро **sing-box** или **Mihomo**, добавить VPN/прокси-узлы, настроить маршрутизацию, DNS, TUN и прозрачный прокси — и запустить всё из браузера.

## Возможности

- **Выбор ядра** и установка/обновление с GitHub (подбор архитектуры: mipsle, mips, arm, arm64, amd64…), зеркало и прокси для загрузки, свой бинарник.
- **Узлы и VPN:** VLESS (Reality, Vision), VMess, Trojan, Shadowsocks, Hysteria2, TUIC, WireGuard (в т.ч. системный интерфейс в sing-box), SOCKS/HTTP; импорт ссылок, подписок и `.conf` WireGuard; генерация ключей WireGuard/Reality и UUID; цепочки узлов, привязка к WAN.
- **Группы:** selector, urltest, fallback, loadbalance (в sing-box fallback/loadbalance заменяются urltest с предупреждением).
- **Маршрутизация:** правила по домену, IP, порту, протоколу, наборам правил (srs/mrs/…), geosite/geoip; порядок, пресеты, исходящий по умолчанию.
- **DNS:** DoH/DoT/UDP, FakeIP, DNS-правила, bootstrap, DNS через прокси.
- **Сеть:** входящие mixed/redirect/tproxy, TUN (stack, auto_route, auto_redirect, strict_route), прозрачный прокси через **nft** или **iptables** для выбранных LAN-интерфейсов с include/exclude клиентов, перехват DNS; просмотр генерируемых скриптов.
- **Расширенные добавки:** любые поля ядра через глубокое слияние JSON (`override_singbox` / `override_mihomo`).
- **Мониторинг:** статус, трафик, подключения, выбор узла и проверка задержки (через Clash API), живые логи.
- **Справочник** функций обоих ядер: [docs/FEATURES.md](docs/FEATURES.md) (также в интерфейсе).
- Безопасность: пароль (PBKDF2), смена при первом входе, HttpOnly/SameSite cookie, защита от CSRF, ограничение перебора.

## Установка

Соберите (нужен Go ≥ 1.24) или возьмите готовые файлы из `dist/`:

```sh
scripts/build.sh 1.0.0        # создаёт dist/corepanel-linux-<arch>
```

Архитектуру роутера покажет `uname -m`; на Keenetic MIPS почти всегда `mipsle`, на OpenWrt смотрите `opkg print-architecture`.

Скопируйте бинарник и `scripts/install.sh` на роутер и выполните:

```sh
sh install.sh /tmp/corepanel-linux-mipsle
# или, если выложили сборки на свой веб-сервер:
COREPANEL_BASE_URL=https://example.com/corepanel sh install.sh
```

Скрипт сам определит OpenWrt/Keenetic, положит бинарник (`/usr/bin` или `/opt/sbin`), создаст init-скрипт (procd / Entware) и запустит панель на порту **8088**. Логин `admin`, пароль печатается при первом запуске (`logread` / `/opt/var/log/corepanel.log`) или задаётся командой `corepanel passwd`.

### Требования к системе

| | OpenWrt | Keenetic |
|---|---|---|
| Пакеты | `kmod-tun`, для tproxy `kmod-nft-tproxy` | компонент «Пакеты OPKG», Entware |
| Каталог данных | `/etc/corepanel` | `/opt/etc/corepanel` |
| Ядра | `/etc/corepanel/bin` или `/opt` (USB) | `/opt/sbin` |
| Фаервол | nft (iptables — если нет nft) | iptables; nft — если есть |

Ядро занимает 30–50 МБ. При установке с GitHub архив не пишется на диск — он распаковывается прямо из потока, поэтому нужно место только под сам бинарник; при обновлении, если две версии не помещаются, старая удаляется автоматически. На роутерах с малой флеш-памятью есть два выхода: подключить USB-накопитель и указать каталог в разделе «Ядро», либо нажать **«Из пакетов системы»** — панель выполнит `opkg install` / `apk add` (пакеты `sing-box`, `mihomo`); сборки из репозиториев обычно компактнее релизов GitHub, но набор функций в них может быть урезан и пакета может не оказаться для вашей прошивки. На Keenetic TUN/TPROXY зависят от модели и прошивки — при отсутствии используйте режим **redirect**.

## Команды

```
corepanel [run] [-listen host:port]
corepanel passwd [пароль]
corepanel features-md
corepanel version
```

Переменные: `COREPANEL_DIR`, `COREPANEL_BIN_DIR`, `COREPANEL_PLATFORM`.

## Устройство проекта

```
cmd/corepanel      точка входа
internal/model     единая модель настроек + валидация
internal/gen       генераторы config.json (sing-box) и config.yaml (Mihomo)
internal/importer  разбор ссылок, подписок, WireGuard .conf
internal/installer загрузка и установка ядер
internal/supervisor запуск ядра, проверка конфига, перезапуск, логи
internal/firewall  nft/iptables для redirect и tproxy
internal/server    HTTP API (+ прокси к Clash API ядра)
internal/features  каталог возможностей ядер
web/static         интерфейс (ES-модули, CSS)
scripts            build.sh, install.sh
```

## Ограничения

- Панель не проверялась на реальных роутерах из среды разработки: логика запуска и фаервола покрыта тестами и генерацией скриптов, но первый запуск на вашей модели стоит проверить (`Конфигурация` → предпросмотр, `Сеть` → просмотр скриптов).
- Сведения в справочнике отражают актуальные релизы на момент написания; детали по версиям сверяйте с документацией ядер.

## Сборка на GitHub по кнопке

Вкладка **Actions → «Сборка corepanel» → Run workflow**: укажите версию, и GitHub соберёт бинарники под 8 архитектур и пакеты `.ipk` для OpenWrt и Entware, прогонит `go vet` и тесты. Файлы появятся в артефактах запуска и (если включена галочка) в разделе **Releases**, вместе с `SHA256SUMS.txt`.
