package gen

import (
	"fmt"
	"strings"

	"corepanel/internal/model"
)

// Mihomo собирает config.yaml для Mihomo (Clash.Meta).
func Mihomo(s *model.Settings) (*Result, error) {
	p := buildPlan(s, model.CoreMihomo)
	res := &Result{Core: model.CoreMihomo, Filename: "config.yaml"}
	root := NewO()

	g := s.General
	if s.Inbounds.MixedPort > 0 {
		root.Set("mixed-port", s.Inbounds.MixedPort)
	}
	if s.Firewall.Mode == "redirect" && s.Inbounds.RedirPort > 0 {
		root.Set("redir-port", s.Inbounds.RedirPort)
	}
	if s.Firewall.Mode == "tproxy" && s.Inbounds.TProxyPort > 0 {
		root.Set("tproxy-port", s.Inbounds.TProxyPort)
	}
	root.Set("allow-lan", g.AllowLAN)
	if g.AllowLAN {
		root.Set("bind-address", "*")
	}
	root.Set("mode", "rule")
	root.Set("log-level", mhLogLevel(g.LogLevel))
	root.Set("ipv6", g.IPv6)
	root.Set("unified-delay", true)
	root.Set("tcp-concurrent", g.TCPConcurrent)
	root.Set("find-process-mode", "off")
	root.Opt("interface-name", g.DefaultInterface)
	root.Opt("external-controller", g.Controller)
	root.Opt("secret", g.Secret)
	root.Opt("external-ui", g.ExternalUI)
	root.Set("profile", NewO().Set("store-selected", true).Set("store-fake-ip", s.DNS.Mode == "fakeip"))
	if g.Sniff {
		root.Set("sniffer", NewO().Set("enable", true).Set("sniff", NewO().
			Set("HTTP", NewO().Set("ports", []any{80, "8080-8880"}).Set("override-destination", true)).
			Set("TLS", NewO().Set("ports", []any{443, 8443})).
			Set("QUIC", NewO().Set("ports", []any{443, 8443}))))
	}

	if s.Tun.Enabled {
		t := NewO().Set("enable", true).Set("stack", s.Tun.Stack).Set("device", s.Tun.Name).
			Set("auto-route", s.Tun.AutoRoute).
			Opt("auto-redirect", s.Tun.AutoRedirect && s.Tun.AutoRoute).
			Set("auto-detect-interface", g.DefaultInterface == "").
			Opt("strict-route", s.Tun.StrictRoute).Opt("mtu", s.Tun.MTU)
		if s.Tun.DNSHijack {
			t.Set("dns-hijack", []string{"any:53", "tcp://any:53"})
		}
		if len(s.Tun.ExcludeCIDR) > 0 {
			t.Set("route-exclude-address", s.Tun.ExcludeCIDR)
		}
		root.Set("tun", t)
	}

	if s.DNS.Enabled {
		d, err := mhDNS(s, p)
		if err != nil {
			return nil, err
		}
		root.Set("dns", d)
	}

	proxies, groups := mhProxies(s, p)
	root.Set("proxies", proxies)
	root.Set("proxy-groups", groups)

	if len(p.sets) > 0 {
		prov := NewO()
		for _, sp := range p.sets {
			o := NewO().Set("type", "http").Set("behavior", sp.Behavior).Set("format", sp.Format).
				Set("url", sp.URL).Set("path", "./ruleset/"+unsafeName.ReplaceAllString(sp.Name, "_")+"."+extFor(sp.Format))
			iv := sp.Interval
			if iv <= 0 {
				iv = 86400
			}
			o.Set("interval", iv)
			if v := s.General.UpdateVia; v != "" && v != "direct" && v != "block" {
				o.Set("proxy", v)
			}
			prov.Set(sp.Name, o)
		}
		root.Set("rule-providers", prov)
	}
	root.Set("rules", mhRules(s, p))

	if len(s.OverrideMihomo) > 0 {
		Merge(root, s.OverrideMihomo)
	}
	res.Config = "# Сгенерировано corepanel — ручные правки будут перезаписаны.\n" + YAML(root)
	res.Warnings = p.warnings
	return res, nil
}

func extFor(format string) string {
	switch format {
	case "mrs":
		return "mrs"
	case "yaml":
		return "yaml"
	}
	return "txt"
}

func mhLogLevel(l string) string {
	switch l {
	case "warn", "":
		return "warning"
	case "debug", "info", "error", "silent":
		return l
	}
	return "warning"
}

func mhTarget(o string) string {
	switch o {
	case "direct":
		return "DIRECT"
	case "block":
		return "REJECT"
	}
	return o
}

// ---------- DNS ----------

// mhDNSAddr превращает адрес в формат Mihomo (https://…, tls://…, quic://…, ip).
func mhDNSAddr(a dnsAddr, raw string) string {
	if a.Type == "local" {
		return "system"
	}
	return strings.TrimSpace(raw)
}

func mhDNS(s *model.Settings, p *plan) (*O, error) {
	remote, err := parseDNSAddr(s.DNS.Remote)
	if err != nil {
		return nil, fmt.Errorf("DNS (remote): %w", err)
	}
	local, err := parseDNSAddr(s.DNS.Local)
	if err != nil {
		return nil, fmt.Errorf("DNS (local): %w", err)
	}
	boot := s.DNS.Bootstrap
	if boot == "" {
		boot = s.DNS.Local
	}
	if a, err := parseDNSAddr(boot); err != nil || !isIP(a.Host) {
		p.warn("DNS bootstrap должен быть IP-адресом — использован 77.88.8.8")
		boot = "77.88.8.8"
	}

	remoteStr := mhDNSAddr(remote, s.DNS.Remote)
	// Mihomo умеет задавать выход для DoH через суффикс #proxy
	detour := s.DNS.RemoteDetour
	if detour == "" {
		detour = s.Final
	}
	if detour != "" && detour != "direct" && detour != "block" && (remote.Type == "https" || remote.Type == "h3" || remote.Type == "tls" || remote.Type == "quic") {
		remoteStr += "#" + detour
	}
	localStr := mhDNSAddr(local, s.DNS.Local)

	d := NewO().Set("enable", true).Set("listen", s.DNS.Listen).Set("ipv6", s.General.IPv6)
	fake := s.DNS.Mode == "fakeip"
	if fake {
		d.Set("enhanced-mode", "fake-ip").Set("fake-ip-range", s.DNS.FakeIPRange)
		filter := []string{"+.lan", "+.local", "+.home.arpa", "time.*.com", "ntp.*.com", "+.ntp.org", "stun.*.*", "+.stun.*.*"}
		d.Set("fake-ip-filter", filter)
	} else {
		d.Set("enhanced-mode", "normal")
	}
	d.Set("default-nameserver", []string{boot})
	if s.DNS.Final == "local" {
		d.Set("nameserver", []string{localStr})
	} else {
		d.Set("nameserver", []string{remoteStr})
	}
	d.Set("proxy-server-nameserver", []string{localStr})

	policy := NewO()
	for _, doms := range chunkDomains(nodeServerDomains(s)) {
		policy.Set(doms, localStr)
	}
	for _, r := range p.dnsRules {
		srv := ""
		switch r.Outbound {
		case "local":
			srv = localStr
		case "remote":
			srv = remoteStr
		default:
			p.warn("DNS-правила с действием block Mihomo не поддерживает — правило пропущено")
			continue
		}
		for _, v := range r.Values {
			var key string
			switch r.Type {
			case "domain":
				key = v
			case "domain_suffix":
				key = "+." + strings.TrimPrefix(v, ".")
			case "domain_keyword":
				key = "*" + v + "*"
			case "rule_set":
				key = "rule-set:" + v
			default:
				p.warn("DNS-правило типа «%s» в Mihomo не поддерживается — пропущено", r.Type)
				continue
			}
			if _, exists := policy.Get(key); !exists {
				policy.Set(key, srv)
			}
		}
	}
	if len(policy.keys) > 0 {
		d.Set("nameserver-policy", policy)
	}
	return d, nil
}

// chunkDomains — каждый домен отдельным ключом (формат nameserver-policy).
func chunkDomains(d []string) []string { return d }

// ---------- узлы ----------

func mhNetwork(n model.Node) string {
	switch n.Network {
	case "httpupgrade":
		return "ws"
	case "", "tcp":
		return ""
	}
	return n.Network
}

func mhTransport(o *O, n model.Node) {
	net := mhNetwork(n)
	if net == "" {
		return
	}
	o.Set("network", net)
	switch n.Network {
	case "ws", "httpupgrade":
		ws := NewO().Opt("path", n.Path)
		if n.Host != "" {
			ws.Set("headers", NewO().Set("Host", n.Host))
		}
		if n.Network == "httpupgrade" {
			ws.Set("v2ray-http-upgrade", true)
		}
		o.Set("ws-opts", ws)
	case "grpc":
		o.Set("grpc-opts", NewO().Opt("grpc-service-name", n.ServiceName))
	case "h2":
		h := NewO()
		if n.Host != "" {
			h.Set("host", []string{n.Host})
		}
		h.Opt("path", n.Path)
		o.Set("h2-opts", h)
	}
}

func mhTLS(o *O, n model.Node, sniKey string) {
	if !hasTLS(n) {
		return
	}
	if n.Type == "vless" || n.Type == "vmess" {
		o.Set("tls", true)
	}
	o.Opt(sniKey, orDefault(n.SNI, hostForSNI(n)))
	o.Opt("skip-cert-verify", n.Insecure)
	alpn := n.ALPN
	if len(alpn) == 0 && (n.Type == "hysteria2" || n.Type == "tuic") {
		alpn = []string{"h3"}
	}
	o.Opt("alpn", alpn)
	if n.Type == "vless" || n.Type == "vmess" || n.Type == "trojan" {
		fp := n.Fingerprint
		if fp == "" && n.Reality {
			fp = "chrome"
		}
		o.Opt("client-fingerprint", fp)
	}
	if n.Reality {
		o.Set("reality-opts", NewO().Set("public-key", n.PublicKey).Opt("short-id", n.ShortID))
	}
}

func mhProxies(s *model.Settings, p *plan) ([]any, []any) {
	var proxies []any
	active := map[string]bool{"direct": true}
	for _, n := range activeNodes(s) {
		active[n.Name] = true
		o := NewO().Set("name", n.Name)
		fail := false
		switch n.Type {
		case "vless":
			o.Set("type", "vless").Set("server", n.Server).Set("port", n.Port).Set("uuid", n.UUID).Opt("flow", n.Flow)
			o.Set("udp", true).Set("packet-encoding", "xudp")
			mhTLS(o, n, "servername")
			mhTransport(o, n)
		case "vmess":
			o.Set("type", "vmess").Set("server", n.Server).Set("port", n.Port).Set("uuid", n.UUID).
				Set("alterId", n.AlterID).Set("cipher", orDefault(n.Method, "auto")).Set("udp", true).Set("packet-encoding", "xudp")
			mhTLS(o, n, "servername")
			mhTransport(o, n)
		case "trojan":
			o.Set("type", "trojan").Set("server", n.Server).Set("port", n.Port).Set("password", n.Password).Set("udp", true)
			mhTLS(o, n, "sni")
			mhTransport(o, n)
		case "shadowsocks":
			o.Set("type", "ss").Set("server", n.Server).Set("port", n.Port).Set("cipher", n.Method).Set("password", n.Password).Set("udp", true)
		case "hysteria2":
			o.Set("type", "hysteria2").Set("server", n.Server).Set("port", n.Port).Set("password", n.Password)
			if n.UpMbps > 0 {
				o.Set("up", fmt.Sprintf("%d Mbps", n.UpMbps))
			}
			if n.DownMbps > 0 {
				o.Set("down", fmt.Sprintf("%d Mbps", n.DownMbps))
			}
			o.Opt("obfs", n.Obfs).Opt("obfs-password", n.ObfsPassword)
			mhTLS(o, n, "sni")
		case "tuic":
			o.Set("type", "tuic").Set("server", n.Server).Set("port", n.Port).Set("uuid", n.UUID).Opt("password", n.Password).
				Set("congestion-controller", orDefault(n.Congestion, "bbr")).
				Set("udp-relay-mode", orDefault(n.UDPRelayMode, "native"))
			mhTLS(o, n, "sni")
		case "socks":
			o.Set("type", "socks5").Set("server", n.Server).Set("port", n.Port).Opt("username", n.Username).Opt("password", n.Password).Set("udp", true)
		case "http":
			o.Set("type", "http").Set("server", n.Server).Set("port", n.Port).Opt("username", n.Username).Opt("password", n.Password)
			if n.TLS {
				o.Set("tls", true).Opt("sni", n.SNI).Opt("skip-cert-verify", n.Insecure)
			}
		case "wireguard":
			o.Set("type", "wireguard").Set("server", n.Server).Set("port", n.Port).
				Set("private-key", n.PrivateKey).Set("public-key", n.PeerPublicKey).Opt("pre-shared-key", n.PreSharedKey)
			v4, v6 := splitAddrs(n.Addresses)
			o.Opt("ip", v4).Opt("ipv6", v6)
			allowed := n.AllowedIPs
			if len(allowed) == 0 {
				allowed = []string{"0.0.0.0/0", "::/0"}
			}
			o.Set("allowed-ips", allowed).Opt("reserved", n.Reserved).Opt("mtu", n.MTU).Set("udp", true).
				Set("remote-dns-resolve", true).Set("dns", []string{"1.1.1.1", "8.8.8.8"})
			if n.System {
				p.warn("узел «%s»: системный интерфейс WireGuard есть только в sing-box — в Mihomo используется встроенный туннель", n.Name)
			}
		case "awg":
			p.warn("узел «%s»: AmneziaWG работает только на ядре amnezia-box — узел пропущен", n.Name)
			fail = true
		default:
			p.warn("узел «%s»: тип «%s» не поддерживается генератором", n.Name, n.Type)
			fail = true
		}
		if fail {
			continue
		}
		o.Opt("dialer-proxy", n.Detour)
		o.Opt("interface-name", n.BindInterface)
		if s.General.TCPFastOpen {
			o.Set("tfo", true)
		}
		proxies = append(proxies, o)
	}

	var groups []any
	for _, g := range s.Groups {
		active[g.Name] = true
	}
	for _, g := range s.Groups {
		var members []string
		for _, m := range g.Members {
			if !active[m] && m != "block" {
				p.warn("группа «%s»: участник «%s» отключён или не существует — пропущен", g.Name, m)
				continue
			}
			members = append(members, mhTarget(m))
		}
		if len(members) == 0 {
			members = []string{"DIRECT"}
			p.warn("группа «%s» осталась пустой — добавлен DIRECT", g.Name)
		}
		o := NewO().Set("name", g.Name)
		switch g.Type {
		case "selector":
			o.Set("type", "select")
		case "urltest":
			o.Set("type", "url-test")
		case "fallback":
			o.Set("type", "fallback")
		case "loadbalance":
			o.Set("type", "load-balance").Set("strategy", "consistent-hashing")
		default:
			o.Set("type", "select")
			p.warn("группа «%s»: неизвестный тип «%s», использован select", g.Name, g.Type)
		}
		o.Set("proxies", members)
		if g.Type != "selector" {
			o.Set("url", orDefault(g.URL, "https://www.gstatic.com/generate_204")).Set("interval", maxInt(g.Interval, 30)).Opt("tolerance", g.Tolerance)
		}
		groups = append(groups, o)
	}
	return proxies, groups
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func splitAddrs(addrs []string) (v4, v6 string) {
	for _, a := range addrs {
		ip := strings.SplitN(a, "/", 2)[0]
		if strings.Contains(ip, ":") {
			if v6 == "" {
				v6 = ip
			}
		} else if v4 == "" {
			v4 = ip
		}
	}
	return
}

// ---------- правила ----------

func mhRules(s *model.Settings, p *plan) []string {
	var rules []string
	if s.General.BypassLAN {
		for _, c := range PrivateCIDRs {
			rules = append(rules, fmt.Sprintf("IP-CIDR%s,%s,DIRECT,no-resolve", v6suffix(c), c))
		}
	}
	for _, r := range p.rules {
		target := mhTarget(r.Outbound)
		for _, v := range r.Values {
			var line string
			switch r.Type {
			case "domain":
				line = "DOMAIN," + v
			case "domain_suffix":
				line = "DOMAIN-SUFFIX," + strings.TrimPrefix(v, ".")
			case "domain_keyword":
				line = "DOMAIN-KEYWORD," + v
			case "domain_regex":
				line = "DOMAIN-REGEX," + v
			case "ip_cidr":
				line = fmt.Sprintf("IP-CIDR%s,%s", v6suffix(v), v)
			case "src_ip_cidr":
				line = "SRC-IP-CIDR," + v
			case "port":
				line = "DST-PORT," + v
			case "port_range":
				line = "DST-PORT," + strings.ReplaceAll(v, ":", "-")
			case "network":
				line = "NETWORK," + strings.ToUpper(v)
			case "rule_set":
				line = "RULE-SET," + v
			default:
				continue
			}
			line += "," + target
			if r.Type == "ip_cidr" || r.Type == "src_ip_cidr" || (r.Type == "rule_set" && p.setBehavior(v) == "ipcidr") {
				line += ",no-resolve"
			}
			rules = append(rules, line)
		}
	}
	rules = append(rules, "MATCH,"+mhTarget(s.Final))
	return rules
}

func (p *plan) setBehavior(name string) string {
	if i, ok := p.setIdx[name]; ok {
		return p.sets[i].Behavior
	}
	return ""
}

func v6suffix(c string) string {
	if strings.Contains(c, ":") {
		return "6"
	}
	return ""
}
