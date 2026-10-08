// Package model описывает единую модель настроек, из которой генерируются
// конфигурации и для sing-box, и для Mihomo.
package model

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

const (
	CoreSingbox = "singbox"
	CoreMihomo  = "mihomo"
)

// Settings — все пользовательские настройки панели.
type Settings struct {
	Version   int    `json:"version"`
	Core      string `json:"core"`      // singbox | mihomo
	Autostart bool   `json:"autostart"` // запускать ядро вместе с панелью

	General  General   `json:"general"`
	Inbounds Inbounds  `json:"inbounds"`
	Tun      Tun       `json:"tun"`
	DNS      DNS       `json:"dns"`
	Nodes    []Node    `json:"nodes"`
	Groups   []Group   `json:"groups"`
	RuleSets []RuleSet `json:"rule_sets"`
	Rules    []Rule    `json:"rules"`
	Final    string    `json:"final"` // исходящий по умолчанию (имя группы/узла/direct)
	Firewall Firewall  `json:"firewall"`

	Download Download `json:"download"`

	// Произвольные добавки к итоговому конфигу (глубокое слияние).
	// Позволяют использовать любую возможность ядра, для которой нет полей в UI.
	OverrideSingbox map[string]any `json:"override_singbox,omitempty"`
	OverrideMihomo  map[string]any `json:"override_mihomo,omitempty"`
}

type General struct {
	LogLevel         string `json:"log_level"` // debug|info|warn|error
	AllowLAN         bool   `json:"allow_lan"` // слушать на 0.0.0.0
	BypassLAN        bool   `json:"bypass_lan"`
	Sniff            bool   `json:"sniff"`
	IPv6             bool   `json:"ipv6"`
	Controller       string `json:"controller"` // адрес Clash API, напр. 127.0.0.1:9090
	Secret           string `json:"secret"`
	ExternalUI       string `json:"external_ui"`       // каталог с дашбордом (zashboard/metacubexd)
	DefaultInterface string `json:"default_interface"` // привязка исходящих к WAN-интерфейсу
	UpdateVia        string `json:"update_via"`        // через какой исходящий качать rule-set'ы
	TCPFastOpen      bool   `json:"tcp_fast_open"`
	TCPConcurrent    bool   `json:"tcp_concurrent"`
}

type Inbounds struct {
	MixedPort  int `json:"mixed_port"`
	RedirPort  int `json:"redir_port"`
	TProxyPort int `json:"tproxy_port"`
}

type Tun struct {
	Enabled      bool     `json:"enabled"`
	Name         string   `json:"name"`
	Address      string   `json:"address"`
	MTU          int      `json:"mtu"`
	Stack        string   `json:"stack"` // system|gvisor|mixed
	AutoRoute    bool     `json:"auto_route"`
	StrictRoute  bool     `json:"strict_route"`
	AutoRedirect bool     `json:"auto_redirect"`
	DNSHijack    bool     `json:"dns_hijack"`
	ExcludeCIDR  []string `json:"exclude_cidr,omitempty"`
}

type DNS struct {
	Enabled      bool   `json:"enabled"`
	Listen       string `json:"listen"` // адрес, на котором ядро слушает DNS (для dnsmasq/редиректа)
	Mode         string `json:"mode"`   // normal | fakeip
	Remote       string `json:"remote"` // https://1.1.1.1/dns-query
	RemoteDetour string `json:"remote_detour"`
	Local        string `json:"local"`     // 77.88.8.8
	Bootstrap    string `json:"bootstrap"` // IP для разрешения имён DoH/DoT серверов
	FakeIPRange  string `json:"fakeip_range"`
	Final        string `json:"final"` // remote | local
	Rules        []Rule `json:"rules,omitempty"`
}

// Node — один исходящий узел (прокси или VPN).
type Node struct {
	Name string `json:"name"`
	Type string `json:"type"` // vless vmess trojan shadowsocks hysteria2 tuic wireguard socks http

	Server string `json:"server"`
	Port   int    `json:"port"`

	UUID     string `json:"uuid,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"`   // shadowsocks cipher / vmess security
	Flow     string `json:"flow,omitempty"`     // xtls-rprx-vision
	AlterID  int    `json:"alter_id,omitempty"` // vmess

	Network     string `json:"network,omitempty"` // tcp ws grpc h2 httpupgrade
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`

	TLS         bool     `json:"tls,omitempty"`
	SNI         string   `json:"sni,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Insecure    bool     `json:"insecure,omitempty"`
	Reality     bool     `json:"reality,omitempty"`
	PublicKey   string   `json:"public_key,omitempty"` // reality
	ShortID     string   `json:"short_id,omitempty"`

	UDP bool `json:"udp,omitempty"`

	// hysteria2 / tuic
	UpMbps       int    `json:"up_mbps,omitempty"`
	DownMbps     int    `json:"down_mbps,omitempty"`
	Obfs         string `json:"obfs,omitempty"`
	ObfsPassword string `json:"obfs_password,omitempty"`
	Congestion   string `json:"congestion,omitempty"`
	UDPRelayMode string `json:"udp_relay_mode,omitempty"`

	// wireguard
	PrivateKey    string   `json:"private_key,omitempty"`
	PeerPublicKey string   `json:"peer_public_key,omitempty"`
	PreSharedKey  string   `json:"pre_shared_key,omitempty"`
	Addresses     []string `json:"addresses,omitempty"`
	AllowedIPs    []string `json:"allowed_ips,omitempty"`
	Reserved      []int    `json:"reserved,omitempty"`
	MTU           int      `json:"mtu,omitempty"`
	System        bool     `json:"system,omitempty"` // sing-box: создать системный интерфейс wg

	Detour        string `json:"detour,omitempty"`         // цепочка через другой узел
	BindInterface string `json:"bind_interface,omitempty"` // выход через конкретный WAN
	Disabled      bool   `json:"disabled,omitempty"`
}

// Group — группа узлов.
type Group struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"` // selector | urltest | fallback | loadbalance
	Members   []string `json:"members"`
	URL       string   `json:"url,omitempty"`
	Interval  int      `json:"interval,omitempty"` // секунды
	Tolerance int      `json:"tolerance,omitempty"`
}

// RuleSet — удалённый набор правил.
type RuleSet struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Format   string `json:"format"`             // srs json (sing-box) | mrs yaml text (mihomo)
	Behavior string `json:"behavior,omitempty"` // mihomo: domain | ipcidr | classical
	Interval int    `json:"interval,omitempty"` // секунды
}

// Rule — правило маршрутизации (или DNS-правило).
type Rule struct {
	Type     string   `json:"type"`
	Values   []string `json:"values,omitempty"`
	Outbound string   `json:"outbound"` // группа/узел, direct, block; для DNS: local|remote|block
	Note     string   `json:"note,omitempty"`
	Disabled bool     `json:"disabled,omitempty"`
}

type Firewall struct {
	Mode        string   `json:"mode"`         // off | redirect | tproxy
	LANIfaces   []string `json:"lan_ifaces"`   // br-lan / br0
	Include     []string `json:"include"`      // проксировать только эти IP/подсети
	Exclude     []string `json:"exclude"`      // не проксировать эти IP/подсети
	DNSRedirect bool     `json:"dns_redirect"` // перехватывать чужой DNS (53) на ядро
	BypassDst   []string `json:"bypass_dst"`   // дополнительные адреса назначения в обход
	Backend     string   `json:"backend"`      // auto | nft | iptables
	FwMark      int      `json:"fwmark"`       // метка для tproxy
	RouteTable  int      `json:"route_table"`  // таблица маршрутизации для tproxy
}

type Download struct {
	Mirror      string `json:"mirror"`       // префикс-зеркало GitHub, напр. https://ghfast.top/
	Proxy       string `json:"proxy"`        // http(s)://host:port для загрузок
	SingboxPath string `json:"singbox_path"` // свой бинарник
	MihomoPath  string `json:"mihomo_path"`
	BinDir      string `json:"bin_dir"` // куда устанавливать ядра
}

// Default возвращает настройки «из коробки».
func Default() *Settings {
	return &Settings{
		Version: 1,
		Core:    CoreSingbox,
		General: General{
			LogLevel: "warn", AllowLAN: true, BypassLAN: true, Sniff: true,
			Controller: "127.0.0.1:9090", UpdateVia: "direct", TCPConcurrent: true,
		},
		Inbounds: Inbounds{MixedPort: 7890, RedirPort: 7892, TProxyPort: 7893},
		Tun: Tun{Name: "tun0", Address: "172.19.0.1/30", MTU: 1500, Stack: "mixed",
			AutoRoute: true, AutoRedirect: true, DNSHijack: true},
		DNS: DNS{Enabled: true, Listen: "127.0.0.1:1053", Mode: "normal",
			Remote: "https://1.1.1.1/dns-query", Local: "77.88.8.8", Bootstrap: "77.88.8.8",
			FakeIPRange: "198.18.0.0/15", Final: "remote"},
		Final: "direct",
		Firewall: Firewall{Mode: "off", Backend: "auto", FwMark: 1, RouteTable: 100,
			LANIfaces: []string{}, Include: []string{}, Exclude: []string{}, BypassDst: []string{}},
		Nodes: []Node{}, Groups: []Group{}, RuleSets: []RuleSet{}, Rules: []Rule{},
	}
}

// Normalize подставляет значения по умолчанию в пустые поля (после загрузки JSON).
func (s *Settings) Normalize() {
	d := Default()
	if s.Core != CoreSingbox && s.Core != CoreMihomo {
		s.Core = d.Core
	}
	if s.General.LogLevel == "" {
		s.General.LogLevel = d.General.LogLevel
	}
	if s.General.Controller == "" {
		s.General.Controller = d.General.Controller
	}
	if s.General.UpdateVia == "" {
		s.General.UpdateVia = "direct"
	}
	if s.Inbounds.MixedPort == 0 && s.Inbounds.RedirPort == 0 && s.Inbounds.TProxyPort == 0 {
		s.Inbounds = d.Inbounds
	}
	if s.Tun.Name == "" {
		s.Tun.Name = d.Tun.Name
	}
	if s.Tun.Address == "" {
		s.Tun.Address = d.Tun.Address
	}
	if s.Tun.Stack == "" {
		s.Tun.Stack = d.Tun.Stack
	}
	if s.Tun.MTU == 0 {
		s.Tun.MTU = d.Tun.MTU
	}
	if s.DNS.Mode == "" {
		s.DNS.Mode = "normal"
	}
	if s.DNS.Listen == "" {
		s.DNS.Listen = d.DNS.Listen
	}
	if s.DNS.Remote == "" {
		s.DNS.Remote = d.DNS.Remote
	}
	if s.DNS.Local == "" {
		s.DNS.Local = d.DNS.Local
	}
	if s.DNS.FakeIPRange == "" {
		s.DNS.FakeIPRange = d.DNS.FakeIPRange
	}
	if s.DNS.Final == "" {
		s.DNS.Final = "remote"
	}
	if s.Final == "" {
		s.Final = "direct"
	}
	if s.Firewall.Mode == "" {
		s.Firewall.Mode = "off"
	}
	if s.Firewall.Backend == "" {
		s.Firewall.Backend = "auto"
	}
	if s.Firewall.FwMark == 0 {
		s.Firewall.FwMark = 1
	}
	if s.Firewall.RouteTable == 0 {
		s.Firewall.RouteTable = 100
	}
	if s.Nodes == nil {
		s.Nodes = []Node{}
	}
	if s.Groups == nil {
		s.Groups = []Group{}
	}
	if s.RuleSets == nil {
		s.RuleSets = []RuleSet{}
	}
	if s.Rules == nil {
		s.Rules = []Rule{}
	}
	if s.Firewall.LANIfaces == nil {
		s.Firewall.LANIfaces = []string{}
	}
	if s.Firewall.Include == nil {
		s.Firewall.Include = []string{}
	}
	if s.Firewall.Exclude == nil {
		s.Firewall.Exclude = []string{}
	}
	if s.Firewall.BypassDst == nil {
		s.Firewall.BypassDst = []string{}
	}
	for i := range s.Groups {
		g := &s.Groups[i]
		if g.Type == "" {
			g.Type = "selector"
		}
		if g.Type != "selector" {
			if g.URL == "" {
				g.URL = "https://www.gstatic.com/generate_204"
			}
			if g.Interval == 0 {
				g.Interval = 180
			}
		}
	}
}

// Issue — замечание к настройкам.
type Issue struct {
	Level   string `json:"level"` // error | warn
	Message string `json:"message"`
}

var reserved = map[string]bool{"direct": true, "block": true, "DIRECT": true, "REJECT": true, "PASS": true, "GLOBAL": true}
var badNameChars = regexp.MustCompile(`[,\n\r"]`)

// SupportedNodeTypes — типы узлов, которые умеет собирать панель.
var SupportedNodeTypes = []string{"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "wireguard", "socks", "http"}

// Validate проверяет настройки и возвращает список замечаний.
func (s *Settings) Validate() []Issue {
	var out []Issue
	add := func(level, f string, a ...any) { out = append(out, Issue{level, fmt.Sprintf(f, a...)}) }

	names := map[string]string{}
	register := func(kind, name string) {
		switch {
		case name == "":
			add("error", "%s без имени", kind)
		case reserved[name]:
			add("error", "%s: имя «%s» зарезервировано", kind, name)
		case badNameChars.MatchString(name):
			add("error", "%s «%s»: в имени нельзя использовать запятую, кавычки и переводы строк", kind, name)
		case names[name] != "":
			add("error", "имя «%s» используется дважды (%s и %s)", name, names[name], kind)
		default:
			names[name] = kind
		}
	}

	for _, n := range s.Nodes {
		register("узел", n.Name)
		if n.Disabled {
			continue
		}
		ok := false
		for _, t := range SupportedNodeTypes {
			if n.Type == t {
				ok = true
			}
		}
		if !ok {
			add("error", "узел «%s»: неизвестный тип «%s»", n.Name, n.Type)
			continue
		}
		if n.Server == "" || n.Port <= 0 || n.Port > 65535 {
			add("error", "узел «%s»: укажите сервер и порт (1–65535)", n.Name)
		}
		switch n.Type {
		case "vless", "vmess":
			if n.UUID == "" {
				add("error", "узел «%s»: нужен UUID", n.Name)
			}
		case "trojan", "hysteria2":
			if n.Password == "" {
				add("error", "узел «%s»: нужен пароль", n.Name)
			}
		case "shadowsocks":
			if n.Method == "" || n.Password == "" {
				add("error", "узел «%s»: нужны метод шифрования и пароль", n.Name)
			}
		case "tuic":
			if n.UUID == "" {
				add("error", "узел «%s»: нужен UUID", n.Name)
			}
		case "wireguard":
			if n.PrivateKey == "" || n.PeerPublicKey == "" || len(n.Addresses) == 0 {
				add("error", "узел «%s»: для WireGuard нужны приватный ключ, публичный ключ пира и адрес интерфейса", n.Name)
			}
		}
		if n.Reality && n.PublicKey == "" {
			add("error", "узел «%s»: для Reality нужен public key", n.Name)
		}
	}
	for _, g := range s.Groups {
		register("группа", g.Name)
	}
	for _, r := range s.RuleSets {
		if r.Name == "" || r.URL == "" {
			add("error", "набор правил: нужны имя и URL")
		}
	}

	exists := func(n string) bool {
		if n == "direct" || n == "block" {
			return true
		}
		_, ok := names[n]
		return ok
	}
	for _, g := range s.Groups {
		if len(g.Members) == 0 {
			add("error", "группа «%s» пуста", g.Name)
		}
		for _, m := range g.Members {
			if !exists(m) {
				add("error", "группа «%s»: нет узла или группы «%s»", g.Name, m)
			}
			if m == g.Name {
				add("error", "группа «%s» ссылается сама на себя", g.Name)
			}
		}
	}
	if cyc := groupCycle(s.Groups); cyc != "" {
		add("error", "циклическая ссылка между группами: %s", cyc)
	}
	for _, n := range s.Nodes {
		if n.Detour != "" && !exists(n.Detour) {
			add("error", "узел «%s»: цепочка через несуществующий «%s»", n.Name, n.Detour)
		}
	}
	if !exists(s.Final) {
		add("error", "исходящий по умолчанию «%s» не существует", s.Final)
	}
	if s.General.UpdateVia != "" && !exists(s.General.UpdateVia) {
		add("warn", "«Скачивать наборы правил через» указывает на несуществующий «%s»", s.General.UpdateVia)
	}
	for i, r := range s.Rules {
		if r.Disabled {
			continue
		}
		if !exists(r.Outbound) {
			add("error", "правило №%d: исходящий «%s» не существует", i+1, r.Outbound)
		}
		if r.Type != "private" && len(r.Values) == 0 {
			add("error", "правило №%d (%s): нет значений", i+1, r.Type)
		}
	}
	for i, r := range s.DNS.Rules {
		if r.Disabled {
			continue
		}
		if r.Outbound != "local" && r.Outbound != "remote" && r.Outbound != "block" {
			add("error", "DNS-правило №%d: сервер должен быть local, remote или block", i+1)
		}
	}
	for _, p := range []struct {
		n string
		v int
	}{{"mixed", s.Inbounds.MixedPort}, {"redirect", s.Inbounds.RedirPort}, {"tproxy", s.Inbounds.TProxyPort}} {
		if p.v < 0 || p.v > 65535 {
			add("error", "порт %s вне диапазона", p.n)
		}
	}
	if s.Tun.Enabled {
		if _, _, err := net.ParseCIDR(s.Tun.Address); err != nil {
			add("error", "TUN: адрес должен быть в формате CIDR, например 172.19.0.1/30")
		}
	}
	for _, list := range [][]string{s.Firewall.Include, s.Firewall.Exclude, s.Firewall.BypassDst} {
		for _, c := range list {
			if !validIPOrCIDR(c) {
				add("error", "брандмауэр: «%s» — не IP и не подсеть", c)
			}
		}
	}
	if s.Firewall.DNSRedirect && s.DNS.Enabled {
		h, _, err := net.SplitHostPort(s.DNS.Listen)
		if err != nil {
			add("error", "DNS: адрес слушателя должен быть вида 0.0.0.0:1053")
		} else if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			add("error", "для перехвата DNS брандмауэром DNS-слушатель должен быть на 0.0.0.0, а не на %s", h)
		}
	}
	if s.Firewall.Mode == "redirect" && s.Inbounds.RedirPort == 0 {
		add("error", "для режима redirect задайте порт redirect")
	}
	if s.Firewall.Mode == "tproxy" && s.Inbounds.TProxyPort == 0 {
		add("error", "для режима tproxy задайте порт tproxy")
	}
	if s.Firewall.Mode != "off" && len(s.Firewall.LANIfaces) == 0 {
		add("warn", "не выбран LAN-интерфейс: брандмауэр будет применён ко всем входящим интерфейсам")
	}
	return out
}

func validIPOrCIDR(v string) bool {
	if net.ParseIP(v) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(v)
	return err == nil
}

func groupCycle(gs []Group) string {
	idx := map[string]*Group{}
	for i := range gs {
		idx[gs[i].Name] = &gs[i]
	}
	state := map[string]int{}
	var stack []string
	var visit func(n string) string
	visit = func(n string) string {
		g, ok := idx[n]
		if !ok {
			return ""
		}
		switch state[n] {
		case 1:
			return strings.Join(append(stack, n), " → ")
		case 2:
			return ""
		}
		state[n] = 1
		stack = append(stack, n)
		for _, m := range g.Members {
			if c := visit(m); c != "" {
				return c
			}
		}
		stack = stack[:len(stack)-1]
		state[n] = 2
		return ""
	}
	for _, g := range gs {
		if c := visit(g.Name); c != "" {
			return c
		}
	}
	return ""
}
