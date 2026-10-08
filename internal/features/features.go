// Package features — каталог возможностей sing-box и Mihomo и того, как каждая
// из них доступна в панели. Данные отдаются в UI (раздел «Справочник») и
// используются для генерации docs/FEATURES.md.
package features

import (
	"fmt"
	"strings"
)

// Уровни поддержки.
const (
	Yes     = "yes"
	Partial = "partial"
	No      = "no"
)

// Как возможность настраивается в панели.
const (
	UI       = "ui"       // есть поля в интерфейсе
	Override = "override" // только через «Расширенные добавки» (глубокое слияние JSON)
	None     = "none"     // панель не поддерживает
)

type Support struct {
	Level string `json:"level"`
	Note  string `json:"note,omitempty"`
}

type Item struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Desc    string  `json:"desc,omitempty"`
	Singbox Support `json:"singbox"`
	Mihomo  Support `json:"mihomo"`
	Panel   string  `json:"panel"`
}

type Category struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Desc  string `json:"desc,omitempty"`
	Items []Item `json:"items"`
}

func s(level string, note ...string) Support {
	return Support{Level: level, Note: strings.Join(note, " ")}
}

func it(id, name, desc string, sb, mh Support, panel string) Item {
	return Item{ID: id, Name: name, Desc: desc, Singbox: sb, Mihomo: mh, Panel: panel}
}

// Catalog возвращает полный каталог. Сведения отражают актуальные релизы на
// момент написания; конкретные версии стоит сверять с документацией ядер.
func Catalog() []Category {
	return []Category{
		{ID: "outbounds", Title: "Протоколы (исходящие)", Desc: "Через какие протоколы ядро выходит в сеть: прокси и VPN.", Items: []Item{
			it("vless", "VLESS (TLS, Reality, XTLS Vision)", "Лёгкий протокол без шифрования собственного слоя; Reality маскирует трафик под чужой TLS-сайт.", s(Yes), s(Yes), UI),
			it("vmess", "VMess", "Классический протокол V2Ray.", s(Yes), s(Yes), UI),
			it("trojan", "Trojan", "Маскируется под HTTPS.", s(Yes), s(Yes), UI),
			it("shadowsocks", "Shadowsocks (в т.ч. SS-2022)", "AEAD и 2022-шифры.", s(Yes), s(Yes), UI),
			it("hysteria2", "Hysteria2", "На QUIC, с контролем скорости (Brutal); хорош на плохих каналах.", s(Yes), s(Yes), UI),
			it("hysteria1", "Hysteria v1", "Устаревший предшественник Hysteria2.", s(Yes), s(Yes), Override),
			it("tuic", "TUIC v5", "UDP/QUIC-прокси.", s(Yes), s(Yes), UI),
			it("wireguard", "WireGuard", "VPN-туннель. В sing-box может создавать системный интерфейс; в Mihomo работает как исходящий внутри процесса.", s(Yes, "outbound/endpoint, system-интерфейс"), s(Yes, "outbound, без системного интерфейса"), UI),
			it("socks-http", "SOCKS5 / HTTP(S)-прокси", "Подключение к обычным прокси.", s(Yes), s(Yes), UI),
			it("anytls", "AnyTLS", "Новый протокол с маскировкой длины пакетов.", s(Yes), s(Yes), Override),
			it("shadowtls", "ShadowTLS", "Обёртка, имитирующая TLS-рукопожатие настоящего сайта.", s(Yes), s(Yes), Override),
			it("ssh", "SSH-туннель", "Прокси через SSH-сервер.", s(Yes), s(Yes), Override),
			it("naive", "NaïveProxy", "Исходящий naive (на уровне Chromium-сетевого стека).", s(Partial, "зависит от версии и сборки"), s(No), Override),
			it("mieru", "Mieru", "", s(No), s(Yes), Override),
			it("snell", "Snell", "", s(No), s(Yes), Override),
			it("ssr", "ShadowsocksR", "Устаревший протокол.", s(No, "удалён"), s(Yes), Override),
			it("tailscale", "Tailscale", "Встроенный узел tailnet.", s(Yes, "endpoint, нужна соответствующая сборка"), s(No), Override),
			it("direct-block", "direct / block / dns", "Служебные исходящие: напрямую, отбросить, ответить на DNS.", s(Yes), s(Yes), UI),
		}},
		{ID: "transport", Title: "Транспорт, TLS и мультиплексирование", Items: []Item{
			it("ws", "WebSocket", "", s(Yes), s(Yes), UI),
			it("grpc", "gRPC", "", s(Yes), s(Yes), UI),
			it("h2", "HTTP/2", "", s(Yes), s(Yes), UI),
			it("httpupgrade", "HTTPUpgrade", "", s(Yes), s(Yes), UI),
			it("xhttp", "XHTTP (SplitHTTP)", "", s(No), s(Yes, "в новых версиях"), Override),
			it("quic-transport", "QUIC-транспорт для V2Ray-протоколов", "", s(Yes), s(No), Override),
			it("utls", "uTLS-отпечатки (chrome, firefox, …)", "Подделка TLS-отпечатка клиента.", s(Yes), s(Yes), UI),
			it("reality", "Reality", "", s(Yes), s(Yes), UI),
			it("ech", "Encrypted Client Hello (ECH)", "", s(Yes), s(Yes), Override),
			it("multiplex", "Мультиплексирование (smux / yamux / h2mux), Brutal", "Несколько потоков в одном соединении.", s(Yes), s(Yes), Override),
			it("tfo", "TCP Fast Open / Multi-Path TCP", "", s(Yes), s(Yes), UI),
			it("dialer", "Опции подключения: bind_interface, routing_mark, цепочки (detour / dialer-proxy)", "Выход через конкретный WAN, цепочки узлов.", s(Yes), s(Yes), UI),
			it("happy-eyeballs", "Happy Eyeballs (параллельное подключение v4/v6)", "", s(Yes), s(Partial, "tcp-concurrent"), UI),
		}},
		{ID: "inbounds", Title: "Входящие подключения", Items: []Item{
			it("mixed", "Mixed (HTTP + SOCKS5 на одном порту)", "", s(Yes), s(Yes), UI),
			it("redirect", "Redirect (прозрачный прокси через iptables/nft REDIRECT)", "TCP-трафик LAN перенаправляется на порт ядра.", s(Yes), s(Yes), UI),
			it("tproxy", "TProxy (TCP + UDP)", "Прозрачный прокси с поддержкой UDP.", s(Yes), s(Yes), UI),
			it("tun", "TUN-интерфейс", "Виртуальный интерфейс, через который идёт весь трафик.", s(Yes), s(Yes), UI),
			it("server-inbounds", "Серверные входящие (VLESS, Trojan, Hysteria2, TUIC, SS, …)", "Роутер как прокси-сервер.", s(Yes), s(Yes, "listeners"), Override),
			it("auth", "Аутентификация и ограничение клиентов LAN", "", s(Yes, "users во входящих"), s(Yes, "authentication, lan-allowed-ips"), Override),
			it("tunnels", "Проброс портов (tunnels)", "", s(Partial, "через direct-входящий"), s(Yes), Override),
		}},
		{ID: "tun", Title: "TUN и системная маршрутизация", Items: []Item{
			it("tun-stack", "Стек TUN: system / gvisor / mixed", "", s(Yes), s(Yes), UI),
			it("auto-route", "auto_route / strict_route", "Автоматическая настройка маршрутов.", s(Yes), s(Yes), UI),
			it("auto-redirect", "auto_redirect (nftables) — меньше нагрузка на CPU", "Обход TUN для TCP на Linux — заметно быстрее на слабых роутерах.", s(Yes, "нужен nft"), s(Yes, "auto-redirect"), UI),
			it("dns-hijack", "Перехват DNS в TUN", "", s(Yes, "правило hijack-dns"), s(Yes, "dns-hijack"), UI),
			it("tun-exclude", "Исключение подсетей из TUN", "", s(Yes), s(Yes), UI),
		}},
		{ID: "routing", Title: "Маршрутизация", Desc: "Правила выбирают исходящий узел/группу по домену, IP, порту, протоколу и т.д.", Items: []Item{
			it("r-domain", "domain / domain_suffix / domain_keyword / domain_regex", "", s(Yes), s(Yes), UI),
			it("r-ip", "ip_cidr / src_ip_cidr", "", s(Yes), s(Yes), UI),
			it("r-port", "Порты и диапазоны портов", "", s(Yes), s(Yes), UI),
			it("r-network", "Сеть (tcp/udp)", "", s(Yes), s(Yes), UI),
			it("r-protocol", "Протокол приложения (sniff: tls, http, quic, bittorrent, …)", "", s(Yes), s(Yes, "sniffer"), UI),
			it("r-private", "Частные адреса (ip_is_private)", "", s(Yes), s(Yes), UI),
			it("r-ruleset", "Наборы правил (rule-set / rule-providers)", "Удалённые списки с автообновлением.", s(Yes, "srs, json"), s(Yes, "mrs, yaml, text"), UI),
			it("r-geo", "geosite / geoip по .dat и .mmdb", "", s(Partial, "удалено в 1.12; заменено rule-set"), s(Yes), UI),
			it("r-logical", "Логические правила AND / OR / NOT", "", s(Yes), s(Yes), Override),
			it("r-subrule", "Подправила (SUB-RULE)", "", s(No), s(Yes), Override),
			it("r-inbound", "Сопоставление по входящему (inbound, in-port, in-type)", "", s(Yes), s(Yes), Override),
			it("r-dscp", "DSCP / метки", "", s(Partial), s(Yes), Override),
			it("r-process", "По имени процесса", "Нужна информация о процессах на устройстве — на роутерах практически не применяется.", s(Partial), s(Partial), None),
			it("r-action", "Действия правил: route, reject, hijack-dns, sniff, route-options", "", s(Yes), s(Partial, "аналоги через типы правил и DNS"), UI),
			it("r-clash-mode", "Режимы (global / rule / direct)", "Переключаются из Clash-совместимых дашбордов.", s(Yes), s(Yes), None),
		}},
		{ID: "groups", Title: "Группы и выбор узла", Items: []Item{
			it("g-selector", "Selector — ручной выбор", "", s(Yes), s(Yes), UI),
			it("g-urltest", "URLTest — самый быстрый по замеру", "", s(Yes), s(Yes), UI),
			it("g-fallback", "Fallback — первый рабочий", "", s(No, "заменяется urltest"), s(Yes), UI),
			it("g-lb", "Load-balance — распределение нагрузки", "", s(No, "заменяется urltest"), s(Yes), UI),
			it("g-relay", "Цепочки узлов", "", s(Yes, "detour"), s(Yes, "dialer-proxy; relay устарел"), UI),
			it("g-providers", "Провайдеры узлов (подписки как источник)", "", s(No), s(Yes, "proxy-providers"), Override),
			it("g-filter", "Фильтрация узлов регулярными выражениями", "", s(Yes, "в urltest/selector через outbound-ы; частично"), s(Yes, "filter / exclude-filter"), Override),
			it("g-persist", "Запоминание выбора селектора между перезапусками", "", s(Yes, "cache_file"), s(Yes, "store-selected"), UI),
		}},
		{ID: "dns", Title: "DNS", Items: []Item{
			it("dns-types", "UDP / TCP / DoT / DoH / DoQ / DoH3", "", s(Yes), s(Yes), UI),
			it("dns-fakeip", "FakeIP", "Мгновенные ответы и маршрутизация по домену без утечек.", s(Yes), s(Yes), UI),
			it("dns-rules", "DNS-правила: выбор сервера по домену", "", s(Yes), s(Yes, "nameserver-policy"), UI),
			it("dns-detour", "DNS через прокси (detour)", "", s(Yes), s(Yes), UI),
			it("dns-bootstrap", "Bootstrap для разрешения имён DoH/DoT", "", s(Yes), s(Yes, "default-nameserver"), UI),
			it("dns-ecs", "EDNS Client Subnet", "", s(Yes), s(Yes), Override),
			it("dns-cache", "Кэш DNS, независимый кэш по серверам", "", s(Yes), s(Yes), Override),
			it("dns-hosts", "hosts / подмена ответов", "", s(Yes), s(Yes), Override),
			it("dns-fallback", "fallback-filter (GeoIP-фильтр ответов)", "", s(No), s(Yes), Override),
			it("dns-respect", "respect-rules — DNS следует правилам маршрутизации", "", s(Yes, "dns.rules + detour"), s(Yes), Override),
			it("dns-dhcp", "DNS из DHCP / systemd-resolved", "", s(Yes), s(No), Override),
			it("dns-server", "Свой DNS-сервер для LAN (dnsmasq → ядро)", "", s(Yes), s(Yes, "dns.listen"), UI),
		}},
		{ID: "api", Title: "API, дашборды и диагностика", Items: []Item{
			it("clash-api", "Clash API (REST, WebSocket)", "Используется дашбордами и самой панелью (трафик, выбор узла, задержка).", s(Yes), s(Yes), UI),
			it("external-ui", "Встроенный дашборд (zashboard, metacubexd)", "", s(Yes), s(Yes), UI),
			it("v2ray-api", "V2Ray stats API", "", s(Partial, "нужна сборка с тегом"), s(No), Override),
			it("logs", "Уровни логов, лог в файл", "", s(Yes), s(Yes), UI),
			it("ntp", "Встроенный NTP-клиент", "Важно для роутеров без RTC (TLS ломается при неверном времени).", s(Yes), s(Yes), Override),
			it("geo-update", "Автообновление баз и наборов правил", "", s(Yes), s(Yes), UI),
		}},
		{ID: "router", Title: "Особенности для роутеров", Items: []Item{
			it("nft", "nftables (OpenWrt, новые прошивки)", "", s(Yes), s(Yes), UI),
			it("ipt", "iptables (Keenetic/Entware, старые OpenWrt)", "", s(Yes), s(Yes), UI),
			it("keenetic", "Keenetic: Entware, /opt, ограниченный TUN/TPROXY", "Если TUN недоступен — режим redirect.", s(Yes), s(Yes), UI),
			it("openwrt", "OpenWrt: procd, kmod-tun, kmod-nft-tproxy", "", s(Yes), s(Yes), UI),
			it("bind-wan", "Привязка исходящих к WAN (несколько провайдеров)", "", s(Yes), s(Yes, "interface-name"), UI),
			it("lan-filter", "Включить/исключить клиентов LAN по IP", "", s(Yes), s(Yes), UI),
			it("memory", "Потребление памяти", "Оценка: sing-box обычно легче на малых объёмах, Mihomo богаче по функциям.", s(Partial, "обычно ~30–60 МБ"), s(Partial, "обычно ~40–80 МБ"), None),
		}},
	}
}

// Markdown возвращает каталог в виде Markdown-таблиц (для docs/FEATURES.md).
func Markdown() string {
	var b strings.Builder
	b.WriteString("# Справочник возможностей sing-box и Mihomo\n\n")
	b.WriteString("Этот файл генерируется командой `corepanel features-md` из `internal/features`.\n\n")
	b.WriteString("Колонка «Панель»: **UI** — настраивается в интерфейсе; **JSON** — через «Расширенные добавки» (глубокое слияние в итоговый конфиг); **—** — не поддерживается панелью.\n\n")
	sym := map[string]string{Yes: "✅", Partial: "◐", No: "❌"}
	pn := map[string]string{UI: "UI", Override: "JSON", None: "—"}
	cell := func(x Support) string {
		if x.Note != "" {
			return sym[x.Level] + " " + x.Note
		}
		return sym[x.Level]
	}
	for _, c := range Catalog() {
		fmt.Fprintf(&b, "## %s\n\n", c.Title)
		if c.Desc != "" {
			fmt.Fprintf(&b, "%s\n\n", c.Desc)
		}
		b.WriteString("| Возможность | sing-box | Mihomo | Панель |\n|---|---|---|---|\n")
		for _, i := range c.Items {
			name := i.Name
			if i.Desc != "" {
				name += " — " + i.Desc
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", strings.ReplaceAll(name, "|", "/"), cell(i.Singbox), cell(i.Mihomo), pn[i.Panel])
		}
		b.WriteString("\n")
	}
	return b.String()
}
