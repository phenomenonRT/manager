# Справочник возможностей sing-box и Mihomo

Этот файл генерируется командой `corepanel features-md` из `internal/features`.

Колонка «Панель»: **UI** — настраивается в интерфейсе; **JSON** — через «Расширенные добавки» (глубокое слияние в итоговый конфиг); **—** — не поддерживается панелью.

## Протоколы (исходящие)

Через какие протоколы ядро выходит в сеть: прокси и VPN.

| Возможность | sing-box | Mihomo | Панель |
|---|---|---|---|
| VLESS (TLS, Reality, XTLS Vision) — Лёгкий протокол без шифрования собственного слоя; Reality маскирует трафик под чужой TLS-сайт. | ✅ | ✅ | UI |
| VMess — Классический протокол V2Ray. | ✅ | ✅ | UI |
| Trojan — Маскируется под HTTPS. | ✅ | ✅ | UI |
| Shadowsocks (в т.ч. SS-2022) — AEAD и 2022-шифры. | ✅ | ✅ | UI |
| Hysteria2 — На QUIC, с контролем скорости (Brutal); хорош на плохих каналах. | ✅ | ✅ | UI |
| Hysteria v1 — Устаревший предшественник Hysteria2. | ✅ | ✅ | JSON |
| TUIC v5 — UDP/QUIC-прокси. | ✅ | ✅ | UI |
| WireGuard — VPN-туннель. В sing-box может создавать системный интерфейс; в Mihomo работает как исходящий внутри процесса. | ✅ outbound/endpoint, system-интерфейс | ✅ outbound, без системного интерфейса | UI |
| SOCKS5 / HTTP(S)-прокси — Подключение к обычным прокси. | ✅ | ✅ | UI |
| AnyTLS — Новый протокол с маскировкой длины пакетов. | ✅ | ✅ | JSON |
| ShadowTLS — Обёртка, имитирующая TLS-рукопожатие настоящего сайта. | ✅ | ✅ | JSON |
| SSH-туннель — Прокси через SSH-сервер. | ✅ | ✅ | JSON |
| NaïveProxy — Исходящий naive (на уровне Chromium-сетевого стека). | ◐ зависит от версии и сборки | ❌ | JSON |
| Mieru | ❌ | ✅ | JSON |
| Snell | ❌ | ✅ | JSON |
| ShadowsocksR — Устаревший протокол. | ❌ удалён | ✅ | JSON |
| Tailscale — Встроенный узел tailnet. | ✅ endpoint, нужна соответствующая сборка | ❌ | JSON |
| direct / block / dns — Служебные исходящие: напрямую, отбросить, ответить на DNS. | ✅ | ✅ | UI |

## Транспорт, TLS и мультиплексирование

| Возможность | sing-box | Mihomo | Панель |
|---|---|---|---|
| WebSocket | ✅ | ✅ | UI |
| gRPC | ✅ | ✅ | UI |
| HTTP/2 | ✅ | ✅ | UI |
| HTTPUpgrade | ✅ | ✅ | UI |
| XHTTP (SplitHTTP) | ❌ | ✅ в новых версиях | JSON |
| QUIC-транспорт для V2Ray-протоколов | ✅ | ❌ | JSON |
| uTLS-отпечатки (chrome, firefox, …) — Подделка TLS-отпечатка клиента. | ✅ | ✅ | UI |
| Reality | ✅ | ✅ | UI |
| Encrypted Client Hello (ECH) | ✅ | ✅ | JSON |
| Мультиплексирование (smux / yamux / h2mux), Brutal — Несколько потоков в одном соединении. | ✅ | ✅ | JSON |
| TCP Fast Open / Multi-Path TCP | ✅ | ✅ | UI |
| Опции подключения: bind_interface, routing_mark, цепочки (detour / dialer-proxy) — Выход через конкретный WAN, цепочки узлов. | ✅ | ✅ | UI |
| Happy Eyeballs (параллельное подключение v4/v6) | ✅ | ◐ tcp-concurrent | UI |

## Входящие подключения

| Возможность | sing-box | Mihomo | Панель |
|---|---|---|---|
| Mixed (HTTP + SOCKS5 на одном порту) | ✅ | ✅ | UI |
| Redirect (прозрачный прокси через iptables/nft REDIRECT) — TCP-трафик LAN перенаправляется на порт ядра. | ✅ | ✅ | UI |
| TProxy (TCP + UDP) — Прозрачный прокси с поддержкой UDP. | ✅ | ✅ | UI |
| TUN-интерфейс — Виртуальный интерфейс, через который идёт весь трафик. | ✅ | ✅ | UI |
| Серверные входящие (VLESS, Trojan, Hysteria2, TUIC, SS, …) — Роутер как прокси-сервер. | ✅ | ✅ listeners | JSON |
| Аутентификация и ограничение клиентов LAN | ✅ users во входящих | ✅ authentication, lan-allowed-ips | JSON |
| Проброс портов (tunnels) | ◐ через direct-входящий | ✅ | JSON |

## TUN и системная маршрутизация

| Возможность | sing-box | Mihomo | Панель |
|---|---|---|---|
| Стек TUN: system / gvisor / mixed | ✅ | ✅ | UI |
| auto_route / strict_route — Автоматическая настройка маршрутов. | ✅ | ✅ | UI |
| auto_redirect (nftables) — меньше нагрузка на CPU — Обход TUN для TCP на Linux — заметно быстрее на слабых роутерах. | ✅ нужен nft | ✅ auto-redirect | UI |
| Перехват DNS в TUN | ✅ правило hijack-dns | ✅ dns-hijack | UI |
| Исключение подсетей из TUN | ✅ | ✅ | UI |

## Маршрутизация

Правила выбирают исходящий узел/группу по домену, IP, порту, протоколу и т.д.

| Возможность | sing-box | Mihomo | Панель |
|---|---|---|---|
| domain / domain_suffix / domain_keyword / domain_regex | ✅ | ✅ | UI |
| ip_cidr / src_ip_cidr | ✅ | ✅ | UI |
| Порты и диапазоны портов | ✅ | ✅ | UI |
| Сеть (tcp/udp) | ✅ | ✅ | UI |
| Протокол приложения (sniff: tls, http, quic, bittorrent, …) | ✅ | ✅ sniffer | UI |
| Частные адреса (ip_is_private) | ✅ | ✅ | UI |
| Наборы правил (rule-set / rule-providers) — Удалённые списки с автообновлением. | ✅ srs, json | ✅ mrs, yaml, text | UI |
| geosite / geoip по .dat и .mmdb | ◐ удалено в 1.12; заменено rule-set | ✅ | UI |
| Логические правила AND / OR / NOT | ✅ | ✅ | JSON |
| Подправила (SUB-RULE) | ❌ | ✅ | JSON |
| Сопоставление по входящему (inbound, in-port, in-type) | ✅ | ✅ | JSON |
| DSCP / метки | ◐ | ✅ | JSON |
| По имени процесса — Нужна информация о процессах на устройстве — на роутерах практически не применяется. | ◐ | ◐ | — |
| Действия правил: route, reject, hijack-dns, sniff, route-options | ✅ | ◐ аналоги через типы правил и DNS | UI |
| Режимы (global / rule / direct) — Переключаются из Clash-совместимых дашбордов. | ✅ | ✅ | — |

## Группы и выбор узла

| Возможность | sing-box | Mihomo | Панель |
|---|---|---|---|
| Selector — ручной выбор | ✅ | ✅ | UI |
| URLTest — самый быстрый по замеру | ✅ | ✅ | UI |
| Fallback — первый рабочий | ❌ заменяется urltest | ✅ | UI |
| Load-balance — распределение нагрузки | ❌ заменяется urltest | ✅ | UI |
| Цепочки узлов | ✅ detour | ✅ dialer-proxy; relay устарел | UI |
| Провайдеры узлов (подписки как источник) | ❌ | ✅ proxy-providers | JSON |
| Фильтрация узлов регулярными выражениями | ✅ в urltest/selector через outbound-ы; частично | ✅ filter / exclude-filter | JSON |
| Запоминание выбора селектора между перезапусками | ✅ cache_file | ✅ store-selected | UI |

## DNS

| Возможность | sing-box | Mihomo | Панель |
|---|---|---|---|
| UDP / TCP / DoT / DoH / DoQ / DoH3 | ✅ | ✅ | UI |
| FakeIP — Мгновенные ответы и маршрутизация по домену без утечек. | ✅ | ✅ | UI |
| DNS-правила: выбор сервера по домену | ✅ | ✅ nameserver-policy | UI |
| DNS через прокси (detour) | ✅ | ✅ | UI |
| Bootstrap для разрешения имён DoH/DoT | ✅ | ✅ default-nameserver | UI |
| EDNS Client Subnet | ✅ | ✅ | JSON |
| Кэш DNS, независимый кэш по серверам | ✅ | ✅ | JSON |
| hosts / подмена ответов | ✅ | ✅ | JSON |
| fallback-filter (GeoIP-фильтр ответов) | ❌ | ✅ | JSON |
| respect-rules — DNS следует правилам маршрутизации | ✅ dns.rules + detour | ✅ | JSON |
| DNS из DHCP / systemd-resolved | ✅ | ❌ | JSON |
| Свой DNS-сервер для LAN (dnsmasq → ядро) | ✅ | ✅ dns.listen | UI |

## API, дашборды и диагностика

| Возможность | sing-box | Mihomo | Панель |
|---|---|---|---|
| Clash API (REST, WebSocket) — Используется дашбордами и самой панелью (трафик, выбор узла, задержка). | ✅ | ✅ | UI |
| Встроенный дашборд (zashboard, metacubexd) | ✅ | ✅ | UI |
| V2Ray stats API | ◐ нужна сборка с тегом | ❌ | JSON |
| Уровни логов, лог в файл | ✅ | ✅ | UI |
| Встроенный NTP-клиент — Важно для роутеров без RTC (TLS ломается при неверном времени). | ✅ | ✅ | JSON |
| Автообновление баз и наборов правил | ✅ | ✅ | UI |

## Особенности для роутеров

| Возможность | sing-box | Mihomo | Панель |
|---|---|---|---|
| nftables (OpenWrt, новые прошивки) | ✅ | ✅ | UI |
| iptables (Keenetic/Entware, старые OpenWrt) | ✅ | ✅ | UI |
| Keenetic: Entware, /opt, ограниченный TUN/TPROXY — Если TUN недоступен — режим redirect. | ✅ | ✅ | UI |
| OpenWrt: procd, kmod-tun, kmod-nft-tproxy | ✅ | ✅ | UI |
| Привязка исходящих к WAN (несколько провайдеров) | ✅ | ✅ interface-name | UI |
| Включить/исключить клиентов LAN по IP | ✅ | ✅ | UI |
| Потребление памяти — Оценка: sing-box обычно легче на малых объёмах, Mihomo богаче по функциям. | ◐ обычно ~30–60 МБ | ◐ обычно ~40–80 МБ | — |

