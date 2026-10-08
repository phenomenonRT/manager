package gen

import (
	"fmt"
	"strings"

	"corepanel/internal/model"
)

// Схема конфигурации: sing-box 1.12 и новее (DNS-серверы с полем type,
// rule actions, endpoints для WireGuard, rule_set вместо geoip/geosite).

// Singbox собирает config.json для sing-box.
func Singbox(s *model.Settings) (*Result, error) {
	p := buildPlan(s, model.CoreSingbox)
	res := &Result{Core: model.CoreSingbox, Filename: "config.json"}
	root := NewO()

	root.Set("log", NewO().Set("level", sbLogLevel(s.General.LogLevel)).Set("timestamp", true))

	if s.DNS.Enabled {
		dns, err := sbDNS(s, p)
		if err != nil {
			return nil, err
		}
		root.Set("dns", dns)
	}

	root.Set("inbounds", sbInbounds(s))

	outbounds, endpoints := sbOutbounds(s, p)
	root.Set("outbounds", outbounds)
	if len(endpoints) > 0 {
		root.Set("endpoints", endpoints)
	}
	root.Set("route", sbRoute(s, p))

	exp := NewO()
	clash := NewO().Set("external_controller", s.General.Controller).Opt("secret", s.General.Secret).Opt("external_ui", s.General.ExternalUI)
	if s.General.Controller != "" {
		exp.Set("clash_api", clash)
	}
	exp.Set("cache_file", NewO().Set("enabled", true).Set("path", "cache.db").Opt("store_fakeip", s.DNS.Enabled && s.DNS.Mode == "fakeip"))
	root.Set("experimental", exp)

	if len(s.OverrideSingbox) > 0 {
		Merge(root, s.OverrideSingbox)
	}

	b, err := JSON(root)
	if err != nil {
		return nil, err
	}
	res.Config = string(b)
	res.Warnings = p.warnings
	return res, nil
}

func sbLogLevel(l string) string {
	switch l {
	case "warning":
		return "warn"
	case "silent", "":
		return "warn"
	}
	return l
}

// ---------- DNS ----------

func sbDNSServer(tag string, a dnsAddr, detour string) *O {
	o := NewO().Set("type", a.Type).Set("tag", tag)
	if a.Type == "local" {
		return o
	}
	o.Set("server", a.Host)
	if a.Port > 0 {
		o.Set("server_port", a.Port)
	}
	if (a.Type == "https" || a.Type == "h3") && a.Path != "" && a.Path != "/dns-query" {
		o.Set("path", a.Path)
	}
	if !isIP(a.Host) {
		o.Set("domain_resolver", "bootstrap")
	}
	if detour != "" && detour != "direct" && detour != "block" {
		o.Set("detour", detour)
	}
	return o
}

func sbDNS(s *model.Settings, p *plan) (*O, error) {
	dns := NewO()
	remote, err := parseDNSAddr(s.DNS.Remote)
	if err != nil {
		return nil, fmt.Errorf("DNS (remote): %w", err)
	}
	local, err := parseDNSAddr(s.DNS.Local)
	if err != nil {
		return nil, fmt.Errorf("DNS (local): %w", err)
	}
	bootAddr := s.DNS.Bootstrap
	if bootAddr == "" {
		bootAddr = s.DNS.Local
	}
	boot, err := parseDNSAddr(bootAddr)
	if err != nil || boot.Type == "local" || !isIP(boot.Host) {
		p.warn("DNS bootstrap должен быть IP-адресом — использован 77.88.8.8")
		boot = dnsAddr{Type: "udp", Host: "77.88.8.8"}
	}

	detour := s.DNS.RemoteDetour
	if detour == "" {
		detour = s.Final
	}
	servers := []any{
		sbDNSServer("bootstrap", boot, ""),
		sbDNSServer("local", local, ""),
		sbDNSServer("remote", remote, detour),
	}
	fake := s.DNS.Mode == "fakeip"
	if fake {
		f := NewO().Set("type", "fakeip").Set("tag", "fakeip").Set("inet4_range", s.DNS.FakeIPRange)
		if s.General.IPv6 {
			f.Set("inet6_range", "fc00::/18")
		}
		servers = append(servers, f)
	}
	dns.Set("servers", servers)

	var rules []any
	if doms := nodeServerDomains(s); len(doms) > 0 {
		rules = append(rules, NewO().Set("domain", doms).Set("action", "route").Set("server", "local"))
	}
	for _, r := range p.dnsRules {
		rule := sbMatch(r)
		if rule == nil {
			continue
		}
		switch r.Outbound {
		case "block":
			rule.Set("action", "reject")
		default:
			rule.Set("action", "route").Set("server", r.Outbound)
		}
		rules = append(rules, rule)
	}
	if fake {
		qt := []string{"A"}
		if s.General.IPv6 {
			qt = append(qt, "AAAA")
		}
		rules = append(rules, NewO().Set("query_type", qt).Set("action", "route").Set("server", "fakeip"))
	}
	if len(rules) > 0 {
		dns.Set("rules", rules)
	}
	final := s.DNS.Final
	if final != "local" {
		final = "remote"
	}
	dns.Set("final", final)
	if !s.General.IPv6 {
		dns.Set("strategy", "ipv4_only")
	}
	return dns, nil
}

// sbMatch превращает правило в условие sing-box (без действия).
func sbMatch(r prule) *O {
	o := NewO()
	switch r.Type {
	case "domain", "domain_suffix", "domain_keyword":
		o.Set(r.Type, r.Values)
	case "domain_regex":
		o.Set("domain_regex", r.Values)
	case "ip_cidr":
		o.Set("ip_cidr", r.Values)
	case "src_ip_cidr":
		o.Set("source_ip_cidr", r.Values)
	case "rule_set":
		o.Set("rule_set", r.Values)
	case "port":
		o.Set("port", toInts(r.Values))
	case "port_range":
		o.Set("port_range", r.Values)
	case "network":
		o.Set("network", r.Values)
	case "protocol":
		o.Set("protocol", r.Values)
	default:
		return nil
	}
	return o
}

func toInts(v []string) []int {
	var out []int
	for _, s := range v {
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// ---------- входящие ----------

func sbInbounds(s *model.Settings) []any {
	var in []any
	l := listen(s)
	if s.Inbounds.MixedPort > 0 {
		in = append(in, NewO().Set("type", "mixed").Set("tag", "mixed-in").Set("listen", l).Set("listen_port", s.Inbounds.MixedPort))
	}
	if s.Firewall.Mode == "redirect" && s.Inbounds.RedirPort > 0 {
		in = append(in, NewO().Set("type", "redirect").Set("tag", "redirect-in").Set("listen", "0.0.0.0").Set("listen_port", s.Inbounds.RedirPort))
	}
	if s.Firewall.Mode == "tproxy" && s.Inbounds.TProxyPort > 0 {
		in = append(in, NewO().Set("type", "tproxy").Set("tag", "tproxy-in").Set("listen", "0.0.0.0").Set("listen_port", s.Inbounds.TProxyPort))
	}
	if s.DNS.Enabled && s.DNS.Listen != "" {
		h, port := hostPort(s.DNS.Listen)
		if port > 0 {
			in = append(in, NewO().Set("type", "direct").Set("tag", "dns-in").Set("listen", h).Set("listen_port", port))
		}
	}
	if s.Tun.Enabled {
		t := NewO().Set("type", "tun").Set("tag", "tun-in").
			Set("interface_name", s.Tun.Name).
			Set("address", []string{s.Tun.Address}).
			Opt("mtu", s.Tun.MTU).
			Set("auto_route", s.Tun.AutoRoute).
			Opt("strict_route", s.Tun.StrictRoute).
			Opt("auto_redirect", s.Tun.AutoRedirect && s.Tun.AutoRoute).
			Set("stack", s.Tun.Stack)
		if len(s.Tun.ExcludeCIDR) > 0 {
			t.Set("route_exclude_address", s.Tun.ExcludeCIDR)
		}
		in = append(in, t)
	}
	return in
}

// ---------- исходящие ----------

func sbOutbounds(s *model.Settings, p *plan) ([]any, []any) {
	outs := []any{NewO().Set("type", "direct").Set("tag", "direct")}
	var eps []any
	active := map[string]bool{"direct": true}

	for _, n := range activeNodes(s) {
		active[n.Name] = true
		if n.Type == "wireguard" {
			eps = append(eps, sbWireGuard(s, n))
			continue
		}
		if o := sbNode(s, p, n); o != nil {
			outs = append(outs, o)
		}
	}
	for _, g := range s.Groups {
		active[g.Name] = true
	}
	for _, g := range s.Groups {
		var members []string
		for _, m := range g.Members {
			switch {
			case m == "block":
				p.warn("группа «%s»: «block» не может быть участником группы в sing-box — пропущено", g.Name)
			case !active[m]:
				p.warn("группа «%s»: участник «%s» отключён или не существует — пропущен", g.Name, m)
			default:
				members = append(members, m)
			}
		}
		if len(members) == 0 {
			members = []string{"direct"}
			p.warn("группа «%s» осталась пустой — добавлен direct", g.Name)
		}
		o := NewO().Set("tag", g.Name)
		switch g.Type {
		case "selector":
			o.Set("type", "selector").Set("outbounds", members)
		case "fallback", "loadbalance", "urltest":
			if g.Type != "urltest" {
				p.warn("группа «%s»: тип %s в sing-box отсутствует — использован urltest", g.Name, g.Type)
			}
			o.Set("type", "urltest").Set("outbounds", members).
				Set("url", orDefault(g.URL, "https://www.gstatic.com/generate_204")).
				Set("interval", durStr(g.Interval)).
				Opt("tolerance", g.Tolerance)
		default:
			o.Set("type", "selector").Set("outbounds", members)
			p.warn("группа «%s»: неизвестный тип «%s», использован selector", g.Name, g.Type)
		}
		outs = append(outs, o)
	}
	return outs, eps
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func sbTLS(n model.Node) *O {
	if !hasTLS(n) {
		return nil
	}
	t := NewO().Set("enabled", true).Opt("server_name", orDefault(n.SNI, hostForSNI(n))).Opt("insecure", n.Insecure)
	alpn := n.ALPN
	if len(alpn) == 0 && (n.Type == "hysteria2" || n.Type == "tuic") {
		alpn = []string{"h3"}
	}
	t.Opt("alpn", alpn)
	if n.Type == "vless" || n.Type == "vmess" || n.Type == "trojan" {
		fp := n.Fingerprint
		if fp == "" && n.Reality {
			fp = "chrome"
		}
		if fp != "" {
			t.Set("utls", NewO().Set("enabled", true).Set("fingerprint", fp))
		}
	}
	if n.Reality {
		t.Set("reality", NewO().Set("enabled", true).Set("public_key", n.PublicKey).Opt("short_id", n.ShortID))
	}
	return t
}

func hostForSNI(n model.Node) string {
	if n.Host != "" && !isIP(n.Host) {
		return n.Host
	}
	if n.Server != "" && !isIP(n.Server) {
		return n.Server
	}
	return ""
}

func sbTransport(n model.Node) *O {
	switch n.Network {
	case "ws":
		t := NewO().Set("type", "ws").Opt("path", n.Path)
		if n.Host != "" {
			t.Set("headers", NewO().Set("Host", n.Host))
		}
		return t
	case "grpc":
		return NewO().Set("type", "grpc").Opt("service_name", n.ServiceName)
	case "h2":
		t := NewO().Set("type", "http")
		if n.Host != "" {
			t.Set("host", []string{n.Host})
		}
		return t.Opt("path", n.Path)
	case "httpupgrade":
		return NewO().Set("type", "httpupgrade").Opt("host", n.Host).Opt("path", n.Path)
	}
	return nil
}

func sbDial(o *O, s *model.Settings, n model.Node) {
	o.Opt("detour", n.Detour)
	o.Opt("bind_interface", n.BindInterface)
	o.Opt("tcp_fast_open", s.General.TCPFastOpen)
}

func sbNode(s *model.Settings, p *plan, n model.Node) *O {
	o := NewO().Set("tag", n.Name)
	srv := func() { o.Set("server", n.Server).Set("server_port", n.Port) }
	switch n.Type {
	case "vless":
		o.Set("type", "vless")
		srv()
		o.Set("uuid", n.UUID).Opt("flow", n.Flow).Set("packet_encoding", "xudp")
		o.Opt("tls", sbTLS(n)).Opt("transport", sbTransport(n))
	case "vmess":
		o.Set("type", "vmess")
		srv()
		o.Set("uuid", n.UUID).Set("security", orDefault(n.Method, "auto")).Set("alter_id", n.AlterID).Set("packet_encoding", "xudp")
		o.Opt("tls", sbTLS(n)).Opt("transport", sbTransport(n))
	case "trojan":
		o.Set("type", "trojan")
		srv()
		o.Set("password", n.Password).Opt("tls", sbTLS(n)).Opt("transport", sbTransport(n))
	case "shadowsocks":
		o.Set("type", "shadowsocks")
		srv()
		o.Set("method", n.Method).Set("password", n.Password)
	case "hysteria2":
		o.Set("type", "hysteria2")
		srv()
		o.Set("password", n.Password).Opt("up_mbps", n.UpMbps).Opt("down_mbps", n.DownMbps)
		if n.Obfs != "" {
			o.Set("obfs", NewO().Set("type", n.Obfs).Set("password", n.ObfsPassword))
		}
		o.Set("tls", sbTLS(n))
	case "tuic":
		o.Set("type", "tuic")
		srv()
		o.Set("uuid", n.UUID).Opt("password", n.Password).
			Set("congestion_control", orDefault(n.Congestion, "bbr")).
			Set("udp_relay_mode", orDefault(n.UDPRelayMode, "native")).
			Set("tls", sbTLS(n))
	case "socks":
		o.Set("type", "socks")
		srv()
		o.Set("version", "5").Opt("username", n.Username).Opt("password", n.Password)
	case "http":
		o.Set("type", "http")
		srv()
		o.Opt("username", n.Username).Opt("password", n.Password).Opt("tls", sbTLS(n))
	default:
		p.warn("узел «%s»: тип «%s» не поддерживается генератором", n.Name, n.Type)
		return nil
	}
	sbDial(o, s, n)
	return o
}

func sbWireGuard(s *model.Settings, n model.Node) *O {
	allowed := n.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	peer := NewO().Set("address", n.Server).Set("port", n.Port).Set("public_key", n.PeerPublicKey).
		Opt("pre_shared_key", n.PreSharedKey).Set("allowed_ips", allowed).Opt("reserved", n.Reserved)
	o := NewO().Set("type", "wireguard").Set("tag", n.Name).
		Set("system", n.System).Opt("mtu", n.MTU).
		Set("address", n.Addresses).Set("private_key", n.PrivateKey).Set("peers", []any{peer})
	if n.System {
		o.Set("name", wgIfaceName(n.Name))
	}
	sbDial(o, s, n)
	return o
}

func wgIfaceName(n string) string {
	out := unsafeName.ReplaceAllString(strings.ToLower(n), "")
	if len(out) > 15 {
		out = out[:15]
	}
	if out == "" {
		out = "wg0"
	}
	return out
}

// ---------- маршрутизация ----------

func sbRoute(s *model.Settings, p *plan) *O {
	r := NewO()
	var rules []any

	if s.DNS.Enabled && s.DNS.Listen != "" {
		if _, port := hostPort(s.DNS.Listen); port > 0 {
			rules = append(rules, NewO().Set("inbound", []string{"dns-in"}).Set("action", "hijack-dns"))
		}
	}
	if s.General.Sniff {
		rules = append(rules, NewO().Set("action", "sniff"))
	}
	rules = append(rules, NewO().Set("protocol", "dns").Set("action", "hijack-dns"))
	if s.General.BypassLAN {
		rules = append(rules, NewO().Set("ip_is_private", true).Set("action", "route").Set("outbound", "direct"))
	}
	for _, pr := range p.rules {
		m := sbMatch(pr)
		if m == nil {
			continue
		}
		if pr.Outbound == "block" {
			m.Set("action", "reject")
		} else {
			m.Set("action", "route").Set("outbound", pr.Outbound)
		}
		rules = append(rules, m)
	}
	if s.Final == "block" {
		rules = append(rules, NewO().Set("network", []string{"tcp", "udp"}).Set("action", "reject"))
	}
	r.Set("rules", rules)

	if len(p.sets) > 0 {
		var sets []any
		for _, sp := range p.sets {
			o := NewO().Set("type", "remote").Set("tag", sp.Name)
			if sp.Format == "json" {
				o.Set("format", "source")
			} else {
				o.Set("format", "binary")
			}
			o.Set("url", sp.URL)
			if v := s.General.UpdateVia; v != "" && v != "direct" && v != "block" {
				o.Set("download_detour", v)
			}
			iv := sp.Interval
			if iv <= 0 {
				iv = 86400
			}
			o.Set("update_interval", durStr(iv))
			sets = append(sets, o)
		}
		r.Set("rule_set", sets)
	}

	if s.Final != "block" {
		r.Set("final", s.Final)
	}
	if s.General.DefaultInterface != "" {
		r.Set("default_interface", s.General.DefaultInterface)
	} else if s.Tun.Enabled {
		r.Set("auto_detect_interface", true)
	}
	if s.DNS.Enabled {
		r.Set("default_domain_resolver", "bootstrap")
	}
	return r
}
