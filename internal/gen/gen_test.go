package gen

import (
	"encoding/json"
	"strings"
	"testing"

	"corepanel/internal/model"
)

func sample() *model.Settings {
	s := model.Default()
	s.Tun.Enabled = true
	s.Firewall.Mode = "redirect"
	s.Nodes = []model.Node{
		{Name: "de-reality", Type: "vless", Server: "de.example.com", Port: 443, UUID: "11111111-2222-3333-4444-555555555555",
			Flow: "xtls-rprx-vision", TLS: true, Reality: true, SNI: "www.microsoft.com", PublicKey: "PUB", ShortID: "ab12", Fingerprint: "chrome"},
		{Name: "nl-ws", Type: "vmess", Server: "1.2.3.4", Port: 443, UUID: "22222222-2222-3333-4444-555555555555",
			Network: "ws", Path: "/ws", Host: "cdn.example.com", TLS: true, SNI: "cdn.example.com"},
		{Name: "hy2", Type: "hysteria2", Server: "hy.example.com", Port: 8443, Password: "pw", UpMbps: 50, DownMbps: 200, Obfs: "salamander", ObfsPassword: "ob"},
		{Name: "ss", Type: "shadowsocks", Server: "5.6.7.8", Port: 8388, Method: "2022-blake3-aes-128-gcm", Password: "cGFzcw=="},
		{Name: "wg", Type: "wireguard", Server: "9.9.9.9", Port: 51820, PrivateKey: "PRIV", PeerPublicKey: "PEER",
			Addresses: []string{"10.8.0.2/32"}, Reserved: []int{1, 2, 3}, MTU: 1380},
	}
	s.Groups = []model.Group{
		{Name: "auto", Type: "urltest", Members: []string{"de-reality", "nl-ws", "hy2"}, URL: "https://www.gstatic.com/generate_204", Interval: 180, Tolerance: 50},
		{Name: "proxy", Type: "selector", Members: []string{"auto", "de-reality", "wg", "direct"}},
		{Name: "fb", Type: "fallback", Members: []string{"ss", "hy2"}},
	}
	s.Rules = []model.Rule{
		{Type: "geosite", Values: []string{"category-ads-all"}, Outbound: "block"},
		{Type: "geoip", Values: []string{"ru"}, Outbound: "direct"},
		{Type: "domain_suffix", Values: []string{"youtube.com", "googlevideo.com"}, Outbound: "proxy"},
		{Type: "port", Values: []string{"22"}, Outbound: "direct"},
		{Type: "private", Outbound: "direct"},
		{Type: "protocol", Values: []string{"bittorrent"}, Outbound: "direct"},
	}
	s.DNS.Rules = []model.Rule{{Type: "domain_suffix", Values: []string{"ru"}, Outbound: "local"}}
	s.Final = "proxy"
	s.Normalize()
	return s
}

func TestSingboxJSONValid(t *testing.T) {
	res, err := Singbox(sample())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(res.Config), &m); err != nil {
		t.Fatalf("невалидный JSON: %v\n%s", err, res.Config)
	}
	for _, k := range []string{"log", "dns", "inbounds", "outbounds", "endpoints", "route", "experimental"} {
		if _, ok := m[k]; !ok {
			t.Errorf("нет раздела %s", k)
		}
	}
	route := m["route"].(map[string]any)
	if route["final"] != "proxy" {
		t.Errorf("final = %v", route["final"])
	}
	if route["default_domain_resolver"] != "bootstrap" {
		t.Errorf("нет default_domain_resolver")
	}
	if route["auto_detect_interface"] != true {
		t.Errorf("нет auto_detect_interface при включённом TUN")
	}
	sets := route["rule_set"].([]any)
	if len(sets) != 2 {
		t.Errorf("ожидалось 2 rule_set (geosite+geoip), получено %d", len(sets))
	}
	// fallback → urltest с огромным допуском, без предупреждения
	if containsWarn(res.Warnings, "fallback") {
		t.Errorf("fallback поддерживается, предупреждения быть не должно: %v", res.Warnings)
	}
	if !strings.Contains(res.Config, `"tolerance": 60000`) {
		t.Errorf("у fallback нет допуска 60000: %s", res.Config)
	}
	if !strings.Contains(res.Config, `"type": "wireguard"`) {
		t.Error("нет wireguard endpoint")
	}
	if !strings.Contains(res.Config, `"reality"`) || !strings.Contains(res.Config, `"public_key": "PUB"`) {
		t.Error("нет reality")
	}
	// inbounds: mixed, redirect, dns-in, tun
	tags := map[string]bool{}
	for _, in := range m["inbounds"].([]any) {
		tags[in.(map[string]any)["tag"].(string)] = true
	}
	for _, want := range []string{"mixed-in", "redirect-in", "dns-in", "tun-in"} {
		if !tags[want] {
			t.Errorf("нет inbound %s", want)
		}
	}
	if tags["tproxy-in"] {
		t.Error("tproxy не должен создаваться в режиме redirect")
	}
}

func TestSingboxRuleOrderAndBlock(t *testing.T) {
	res, _ := Singbox(sample())
	var m map[string]any
	_ = json.Unmarshal([]byte(res.Config), &m)
	rules := m["route"].(map[string]any)["rules"].([]any)
	first := rules[0].(map[string]any)
	if first["action"] != "hijack-dns" {
		t.Errorf("первым правилом должен быть hijack для dns-in: %v", first)
	}
	var sawSniff, sawReject bool
	for _, r := range rules {
		rm := r.(map[string]any)
		if rm["action"] == "sniff" {
			sawSniff = true
		}
		if rm["action"] == "reject" {
			sawReject = true
		}
	}
	if !sawSniff || !sawReject {
		t.Errorf("sniff=%v reject=%v", sawSniff, sawReject)
	}
}

func TestSingboxDNSFakeIP(t *testing.T) {
	s := sample()
	s.DNS.Mode = "fakeip"
	res, err := Singbox(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Config, `"type": "fakeip"`) || !strings.Contains(res.Config, `"inet4_range": "198.18.0.0/15"`) {
		t.Error("нет fakeip-сервера")
	}
	if !strings.Contains(res.Config, `"server": "fakeip"`) {
		t.Error("нет правила на fakeip")
	}
}

func TestSingboxOverrideMerge(t *testing.T) {
	s := sample()
	s.OverrideSingbox = map[string]any{
		"log":        map[string]any{"level": "debug"},
		"+outbounds": []any{map[string]any{"type": "direct", "tag": "my-direct"}},
	}
	res, _ := Singbox(s)
	if !strings.Contains(res.Config, `"level": "debug"`) {
		t.Error("override log не применён")
	}
	if !strings.Contains(res.Config, `"my-direct"`) {
		t.Error("добавление в outbounds не сработало")
	}
	if !strings.Contains(res.Config, `"timestamp": true`) {
		t.Error("слияние затёрло соседние ключи")
	}
}

func TestMihomoYAML(t *testing.T) {
	res, err := Mihomo(sample())
	if err != nil {
		t.Fatal(err)
	}
	c := res.Config
	for _, want := range []string{
		"mixed-port: 7890", "redir-port: 7892", "proxy-groups:", "rule-providers:",
		`type: "vless"`, `reality-opts:`, `public-key: "PUB"`, `type: "hysteria2"`, `up: "50 Mbps"`,
		`type: "wireguard"`, `type: "ss"`, `type: "url-test"`, `type: "fallback"`,
		`"MATCH,proxy"`, `"RULE-SET,geoip-ru,DIRECT,no-resolve"`, `"RULE-SET,geosite-category-ads-all,REJECT"`,
		`"DOMAIN-SUFFIX,youtube.com,proxy"`, `"DST-PORT,22,DIRECT"`, `enhanced-mode: "normal"`,
		`"+.ru": "77.88.8.8"`, `behavior: "ipcidr"`, `format: "mrs"`,
	} {
		if !strings.Contains(c, want) {
			t.Errorf("в YAML нет %q", want)
		}
	}
	if strings.Contains(c, "IP-CIDR-CIDR") {
		t.Error("неверный тип правила IP-CIDR")
	}
	if !containsWarn(res.Warnings, "sniffed") {
		t.Errorf("нет предупреждения про protocol: %v", res.Warnings)
	}
	if !strings.Contains(c, `"IP-CIDR6,fc00::/7,DIRECT,no-resolve"`) {
		t.Error("нет IPv6-правил для локальных сетей")
	}
}

func TestMihomoWireGuard(t *testing.T) {
	res, _ := Mihomo(sample())
	if !strings.Contains(res.Config, `ip: "10.8.0.2"`) || !strings.Contains(res.Config, "reserved:") {
		t.Error("поля WireGuard выведены неверно")
	}
}

func TestYAMLEmitter(t *testing.T) {
	o := NewO().Set("a", 1).Set("list", []any{
		NewO().Set("name", "x").Set("opts", NewO().Set("k", "v")),
		"plain",
	}).Set("empty", []string{}).Set("yes", true).Set("+.example.com", "x")
	got := YAML(o)
	want := "a: 1\nlist:\n  - name: \"x\"\n    opts:\n      k: \"v\"\n  - \"plain\"\nempty: []\n\"yes\": true\n\"+.example.com\": \"x\"\n"
	if got != want {
		t.Errorf("YAML:\n%s\nожидалось:\n%s", got, want)
	}
}

func TestParseDNSAddr(t *testing.T) {
	cases := map[string]dnsAddr{
		"77.88.8.8":                 {Type: "udp", Host: "77.88.8.8", Scheme: "udp"},
		"https://1.1.1.1/dns-query": {Type: "https", Host: "1.1.1.1", Path: "/dns-query", Scheme: "https"},
		"tls://dns.google:853":      {Type: "tls", Host: "dns.google", Port: 853, Scheme: "tls"},
		"local":                     {Type: "local"},
	}
	for in, want := range cases {
		got, err := parseDNSAddr(in)
		if err != nil || got != want {
			t.Errorf("%s → %+v, %v (ожидалось %+v)", in, got, err, want)
		}
	}
	if _, err := parseDNSAddr("ftp://x"); err == nil {
		t.Error("ftp должен быть отклонён")
	}
}

func TestMirrorAppliedToGeoSets(t *testing.T) {
	s := sample()
	s.Download.Mirror = "https://mirror.example/"
	res, _ := Singbox(s)
	if !strings.Contains(res.Config, "https://mirror.example/https://raw.githubusercontent.com/SagerNet/sing-geoip") {
		t.Error("зеркало не применено")
	}
}

func containsWarn(ws []string, sub string) bool {
	for _, w := range ws {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestAmneziaAWG(t *testing.T) {
	s := sample()
	s.Core = model.CoreAmnezia
	s.Nodes = append(s.Nodes, model.Node{Name: "awg1", Type: "awg", Server: "1.2.3.4", Port: 51820, PrivateKey: "P", PeerPublicKey: "Q",
		PreSharedKey: "PSK", Addresses: []string{"10.8.0.2/32"}, AWG: &model.AWG{Jc: 4, Jmin: 40, Jmax: 70, S1: 10, H1: "1234-5678"}})
	if hasError(s.Validate()) {
		t.Fatalf("validate: %v", s.Validate())
	}
	res, err := Singbox(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{`"type": "awg"`, `"jc": 4`, `"jmin": 40`, `"h1": "1234-5678"`, `"preshared_key": "PSK"`} {
		if !strings.Contains(res.Config, w) {
			t.Errorf("нет %s", w)
		}
	}
	one := model.Settings{}
	ep, _ := json.Marshal(sbAWG(&one, s.Nodes[len(s.Nodes)-1]))
	if !strings.Contains(string(ep), "preshared_key") || strings.Contains(string(ep), "pre_shared_key") || strings.Contains(string(ep), `"system"`) {
		t.Errorf("в схеме amnezia-box нет pre_shared_key и system для awg: %s", ep)
	}
	if strings.Contains(res.Config, `"s2"`) {
		t.Error("нулевой s2 не должен выводиться")
	}
	s.Core = model.CoreSingbox
	if !hasError(s.Validate()) {
		t.Error("awg на sing-box должен давать ошибку")
	}
}

func hasError(is []model.Issue) bool {
	for _, i := range is {
		if i.Level == "error" {
			return true
		}
	}
	return false
}

func TestIfaceNode(t *testing.T) {
	s := model.Default()
	s.Nodes = []model.Node{{Name: "sstp", Type: "iface", BindInterface: "sstp-vpn0"}}
	if issues := s.Validate(); func() bool {
		for _, i := range issues {
			if i.Level == "error" && strings.Contains(i.Message, "sstp") {
				return true
			}
		}
		return false
	}() {
		t.Fatalf("валидация: %v", issues)
	}
	res, err := Singbox(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Config), `"bind_interface": "sstp-vpn0"`) {
		t.Errorf("нет bind_interface: %s", res.Config)
	}
	s.Nodes[0].BindInterface = ""
	for _, i := range s.Validate() {
		if i.Level == "error" && strings.Contains(i.Message, "sstp") {
			return
		}
	}
	t.Error("пустой интерфейс должен давать ошибку")
}

func TestAmneziaRuleSetHTTPClient(t *testing.T) {
	s := sample()
	s.Core = model.CoreAmnezia
	s.RuleSets = []model.RuleSet{{Name: "geosite-youtube", URL: "https://example.com/a.srs", Format: "srs"}}
	s.Rules = append(s.Rules, model.Rule{Type: "rule_set", Values: []string{"geosite-youtube"}, Outbound: "direct"})
	res, err := Singbox(s)
	if err != nil {
		t.Fatal(err)
	}
	c := string(res.Config)
	if !strings.Contains(c, `"http_clients"`) || !strings.Contains(c, `"http_client": "rules-dl"`) || strings.Contains(c, "download_detour") {
		t.Errorf("ожидался явный http_client:\n%s", c)
	}
	// прямая загрузка: detour не задаётся (ядро 1.14 отвергает detour на пустой direct)
	i := strings.Index(c, `"http_clients"`)
	if seg := c[i : i+120]; strings.Contains(seg, `"detour"`) {
		t.Errorf("для direct detour быть не должно: %s", seg)
	}
	s.General.UpdateVia = "proxy"
	res, _ = Singbox(s)
	c = string(res.Config)
	i = strings.Index(c, `"http_clients"`)
	if !strings.Contains(c[i:i+120], `"detour": "proxy"`) {
		t.Errorf("через proxy detour обязателен: %s", c[i:i+120])
	}
}

func TestLogNone(t *testing.T) {
	s := model.Default()
	s.General.LogLevel = "none"
	res, err := Singbox(s)
	if err != nil {
		t.Fatal(err)
	}
	c := string(res.Config)
	if !strings.Contains(c, `"disabled": true`) || strings.Contains(c, `"timestamp"`) {
		t.Errorf("sing-box: журнал не отключён: %s", c)
	}
	if mhLogLevel("none") != "silent" {
		t.Errorf("mihomo: ожидался silent")
	}
	s.General.LogLevel = "warn"
	res, _ = Singbox(s)
	if strings.Contains(string(res.Config), `"disabled"`) {
		t.Errorf("при warn журнал должен быть включён")
	}
}

func TestSingboxFallbackOrder(t *testing.T) {
	s := model.Default()
	s.Nodes = []model.Node{
		{Name: "a", Type: "shadowsocks", Server: "1.1.1.1", Port: 1, Method: "aes-128-gcm", Password: "x"},
		{Name: "b", Type: "shadowsocks", Server: "2.2.2.2", Port: 2, Method: "aes-128-gcm", Password: "x"},
	}
	s.Groups = []model.Group{{Name: "fb", Type: "fallback", Members: []string{"a", "b"}}, {Name: "lb", Type: "loadbalance", Members: []string{"a", "b"}}}
	res, err := Singbox(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Config, `"tolerance": 60000`) == false || !strings.Contains(res.Config, `"interval": "1m"`) {
		t.Errorf("fallback: нет допуска или интервала 1m: %s", res.Config)
	}
	if !containsWarn(res.Warnings, "loadbalance") {
		t.Errorf("loadbalance должен давать предупреждение: %v", res.Warnings)
	}
	// порядок участников сохранён — от него зависит «первый рабочий»
	i, j := strings.Index(res.Config, `"a",`), strings.Index(res.Config, `"b"`)
	if i < 0 || j < 0 || i > j {
		t.Errorf("порядок участников нарушен")
	}
}

func TestUrltestToleranceClamp(t *testing.T) {
	s := model.Default()
	s.Nodes = []model.Node{{Name: "a", Type: "shadowsocks", Server: "1.1.1.1", Port: 1, Method: "aes-128-gcm", Password: "x"}}
	s.Groups = []model.Group{{Name: "u", Type: "urltest", Members: []string{"a"}, Interval: 300, Tolerance: 120000}}
	res, err := Singbox(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Config, `"tolerance": 60000`) || !strings.Contains(res.Config, `"interval": "5m"`) {
		t.Errorf("допуск не ограничен 60000 мс или интервал не 5m: %s", res.Config)
	}
}

func TestAWG3Fields(t *testing.T) {
	n := model.Node{Name: "a", Type: "awg", Server: "1.2.3.4", Port: 51305, PrivateKey: "K", PeerPublicKey: "P", Addresses: []string{"10.0.0.2/32"},
		Keepalive: "25-27", AWG: &model.AWG{Jc: 5, HeaderProtectionKey: "HPK", RandomTrailers: true, RekeyTimeout: "5", ContentPadding: "11-94"}}
	b, _ := json.Marshal(sbAWG(&model.Settings{}, n))
	for _, w := range []string{`"header_protection_key":"HPK"`, `"random_trailers":true`, `"rekey_timeout":"5"`, `"content_padding_addition":"11-94"`, `"persistent_keepalive_interval":"25-27"`} {
		if !strings.Contains(string(b), w) {
			t.Errorf("нет %s в %s", w, b)
		}
	}
	n.Keepalive = ""
	b, _ = json.Marshal(sbAWG(&model.Settings{}, n))
	if !strings.Contains(string(b), `"persistent_keepalive_interval":25`) {
		t.Errorf("по умолчанию keepalive должен быть числом 25: %s", b)
	}
}

func TestDNSDisabledKeepsCoreResolver(t *testing.T) {
	s := model.Default()
	s.DNS.Enabled = false
	s.Nodes = []model.Node{{Name: "a", Type: "shadowsocks", Server: "1.1.1.1", Port: 1, Method: "aes-128-gcm", Password: "x"}}
	res, err := Singbox(s)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(res.Config), &root); err != nil {
		t.Fatal(err)
	}
	dns, _ := root["dns"].(map[string]any)
	if dns == nil || dns["final"] != "bootstrap" {
		t.Fatalf("при выключенном DNS ядру нужен свой резолвер (bootstrap по IP): %v", root["dns"])
	}
	route := root["route"].(map[string]any)
	if route["default_domain_resolver"] != "bootstrap" {
		t.Errorf("нет default_domain_resolver при выключенном DNS")
	}
	if strings.Contains(res.Config, `"hijack-dns"`) {
		t.Errorf("при выключенном DNS перехват DNS (hijack-dns) должен быть выключен: иначе клиенты получают REFUSED")
	}
}

func TestTunStrictRoute(t *testing.T) {
	s := sample()
	s.Tun.AutoRoute, s.Tun.StrictRoute = true, true
	res, err := Singbox(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Config, `"strict_route": true`) {
		t.Errorf("strict_route не попал в TUN: %s", res.Config)
	}
	s.Tun.StrictRoute = false
	res, _ = Singbox(s)
	if strings.Contains(res.Config, "strict_route") {
		t.Errorf("выключенный strict_route не должен выводиться")
	}
}

func TestTextRuleSetLocalOnSingbox(t *testing.T) {
	s := model.Default()
	s.Core = model.CoreAmnezia
	s.RuleSets = []model.RuleSet{{Name: "set-2", URL: "https://raw.githubusercontent.com/x/y/main/inside-raw.lst"}}
	s.Rules = []model.Rule{{Type: "rule_set", Values: []string{"set-2"}, Outbound: "direct"}}
	res, err := Singbox(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "set-2") {
			t.Fatalf("лишнее предупреждение: %s", w)
		}
	}
	for _, want := range []string{`"type": "local"`, `"path": "rulesets/set-2.json"`, `"format": "source"`} {
		if !strings.Contains(res.Config, want) && !strings.Contains(strings.ReplaceAll(res.Config, `":"`, `": "`), want) {
			t.Fatalf("нет %s:\n%s", want, res.Config)
		}
	}
}

func TestLocalDNSDetour(t *testing.T) {
	s := sample()
	s.DNS.Enabled = true
	s.DNS.Local = "77.88.8.8"
	s.DNS.LocalDetour = s.Nodes[0].Name
	res, err := Singbox(s)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(res.Config), &m); err != nil {
		t.Fatal(err)
	}
	dns := m["dns"].(map[string]any)
	found := false
	for _, x := range dns["servers"].([]any) {
		sv := x.(map[string]any)
		if sv["tag"] == "local" {
			found = sv["detour"] == s.Nodes[0].Name
		}
	}
	if !found {
		t.Fatalf("local DNS без detour: %s", res.Config)
	}
	for _, x := range dns["rules"].([]any) {
		r := x.(map[string]any)
		if _, ok := r["domain"]; ok && r["server"] == "local" {
			t.Fatal("имена узлов не должны идти через Local, который сам ходит через узел")
		}
	}
	if mh, err := Mihomo(s); err != nil || !strings.Contains(mh.Config, "#"+s.Nodes[0].Name) {
		t.Fatalf("mihomo: %v", err)
	}
}
