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
	// fallback → urltest с предупреждением
	if !containsWarn(res.Warnings, "fallback") {
		t.Errorf("нет предупреждения про fallback: %v", res.Warnings)
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
