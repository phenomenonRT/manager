package gen

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"

	"corepanel/internal/model"
)

// Result — итог генерации конфигурации.
type Result struct {
	Core     string   `json:"core"`
	Filename string   `json:"filename"`
	Config   string   `json:"config"`
	Warnings []string `json:"warnings"`
}

// PrivateCIDRs — адреса локальных сетей (раскрываются из правила «private»).
var PrivateCIDRs = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
	"169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128",
}

// setSpec — набор правил, нормализованный под конкретное ядро.
type setSpec struct {
	Name     string
	URL      string
	Format   string // srs|json|mrs|yaml|text
	Behavior string // для Mihomo
	Interval int
	Auto     bool
}

type prule struct {
	Type     string // domain domain_suffix domain_keyword domain_regex ip_cidr src_ip_cidr rule_set port port_range network protocol
	Values   []string
	Outbound string
}

type plan struct {
	core     string
	warnings []string
	sets     []setSpec
	setIdx   map[string]int
	rules    []prule
	dnsRules []prule
}

func (p *plan) warn(f string, a ...any) { p.warnings = append(p.warnings, fmt.Sprintf(f, a...)) }

func formatCore(format string) string {
	switch format {
	case "srs", "json":
		return model.CoreSingbox
	case "mrs", "yaml", "text":
		return model.CoreMihomo
	}
	return ""
}

func guessFormat(u string) string {
	if pu, err := url.Parse(u); err == nil {
		switch strings.ToLower(path.Ext(pu.Path)) {
		case ".srs":
			return "srs"
		case ".json":
			return "json"
		case ".mrs":
			return "mrs"
		case ".yaml", ".yml":
			return "yaml"
		case ".txt", ".list":
			return "text"
		}
	}
	return ""
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._!@-]`)

func geoSetName(kind, name string) string { return kind + "-" + strings.ToLower(name) }

func (p *plan) geoURL(s *model.Settings, kind, name string) string {
	var u string
	if p.core == model.CoreSingbox {
		if kind == "geosite" {
			u = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-" + name + ".srs"
		} else {
			u = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-" + name + ".srs"
		}
	} else {
		if kind == "geosite" {
			u = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/" + name + ".mrs"
		} else {
			u = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/" + name + ".mrs"
		}
	}
	if m := strings.TrimSpace(s.Download.Mirror); m != "" && (s.General.UpdateVia == "" || s.General.UpdateVia == "direct") {
		u = strings.TrimRight(m, "/") + "/" + u
	}
	return u
}

func (p *plan) addSet(sp setSpec) {
	if i, ok := p.setIdx[sp.Name]; ok {
		_ = i
		return
	}
	p.setIdx[sp.Name] = len(p.sets)
	p.sets = append(p.sets, sp)
}

func clean(vals []string) []string {
	var out []string
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// buildPlan приводит правила к виду, понятному выбранному ядру.
func buildPlan(s *model.Settings, core string) *plan {
	p := &plan{core: core, setIdx: map[string]int{}}

	// пользовательские наборы правил, подходящие этому ядру
	userSets := map[string]bool{}
	for _, rs := range s.RuleSets {
		f := rs.Format
		if f == "" {
			f = guessFormat(rs.URL)
		}
		if f == "" {
			p.warn("набор правил «%s»: не удалось определить формат по URL — укажите его вручную, набор пропущен", rs.Name)
			continue
		}
		if formatCore(f) != core {
			p.warn("набор правил «%s» (формат %s) не подходит для выбранного ядра и пропущен", rs.Name, f)
			continue
		}
		beh := rs.Behavior
		if core == model.CoreMihomo && beh == "" {
			if f == "mrs" {
				beh = "domain"
			} else {
				beh = "classical"
			}
		}
		p.addSet(setSpec{Name: rs.Name, URL: rs.URL, Format: f, Behavior: beh, Interval: rs.Interval})
		userSets[rs.Name] = true
	}

	convert := func(rules []model.Rule, dns bool) []prule {
		var out []prule
		for i, r := range rules {
			if r.Disabled {
				continue
			}
			label := fmt.Sprintf("правило №%d", i+1)
			if dns {
				label = fmt.Sprintf("DNS-правило №%d", i+1)
			}
			vals := clean(r.Values)
			t := r.Type
			switch t {
			case "private":
				t, vals = "ip_cidr", append([]string(nil), PrivateCIDRs...)
			case "geosite", "geoip":
				var names []string
				for _, v := range vals {
					v = strings.ToLower(v)
					n := geoSetName(t, v)
					beh := "domain"
					if t == "geoip" {
						beh = "ipcidr"
					}
					f := "srs"
					if core == model.CoreMihomo {
						f = "mrs"
					}
					p.addSet(setSpec{Name: n, URL: p.geoURL(s, t, v), Format: f, Behavior: beh, Interval: 86400, Auto: true})
					names = append(names, n)
				}
				t, vals = "rule_set", names
			case "rule_set":
				var ok []string
				for _, v := range vals {
					if userSets[v] || p.hasSet(v) {
						ok = append(ok, v)
					} else {
						p.warn("%s: набор «%s» не найден или не подходит для ядра — значение пропущено", label, v)
					}
				}
				vals = ok
			case "protocol":
				if core == model.CoreMihomo {
					p.warn("%s: сопоставление по sniffed-протоколу есть только у sing-box — правило пропущено", label)
					continue
				}
			case "domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "src_ip_cidr", "port", "port_range", "network":
			default:
				p.warn("%s: неизвестный тип «%s» — пропущено", label, t)
				continue
			}
			if len(vals) == 0 {
				continue
			}
			if t == "port_range" {
				for i := range vals {
					vals[i] = strings.ReplaceAll(vals[i], "-", ":")
				}
			}
			out = append(out, prule{Type: t, Values: vals, Outbound: r.Outbound})
		}
		return out
	}
	p.rules = convert(s.Rules, false)
	p.dnsRules = convert(s.DNS.Rules, true)
	return p
}

func (p *plan) hasSet(name string) bool { _, ok := p.setIdx[name]; return ok }

// ---------- общие вспомогательные ----------

func durStr(sec int) string {
	switch {
	case sec <= 0:
		return "3m"
	case sec%3600 == 0:
		return fmt.Sprintf("%dh", sec/3600)
	case sec%60 == 0:
		return fmt.Sprintf("%dm", sec/60)
	}
	return fmt.Sprintf("%ds", sec)
}

func listen(s *model.Settings) string {
	if s.General.AllowLAN {
		return "0.0.0.0"
	}
	return "127.0.0.1"
}

func hostPort(addr string) (string, int) {
	h, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	var port int
	fmt.Sscanf(ps, "%d", &port)
	return h, port
}

func isIP(h string) bool { return net.ParseIP(h) != nil }

// dnsAddr — разобранный адрес DNS-сервера.
type dnsAddr struct {
	Type   string // local udp tcp tls https quic h3
	Host   string
	Port   int
	Path   string
	Scheme string
}

func parseDNSAddr(a string) (dnsAddr, error) {
	a = strings.TrimSpace(a)
	if a == "" {
		return dnsAddr{}, fmt.Errorf("пустой адрес DNS")
	}
	if a == "local" {
		return dnsAddr{Type: "local"}, nil
	}
	if !strings.Contains(a, "://") {
		a = "udp://" + a
	}
	u, err := url.Parse(a)
	if err != nil || u.Hostname() == "" {
		return dnsAddr{}, fmt.Errorf("не удалось разобрать адрес DNS «%s»", a)
	}
	d := dnsAddr{Host: u.Hostname(), Scheme: u.Scheme}
	if ps := u.Port(); ps != "" {
		fmt.Sscanf(ps, "%d", &d.Port)
	}
	switch u.Scheme {
	case "udp", "tcp", "tls", "quic":
		d.Type = u.Scheme
	case "https", "h3":
		d.Type = u.Scheme
		d.Path = u.Path
	default:
		return dnsAddr{}, fmt.Errorf("схема «%s» не поддерживается (udp, tcp, tls, https, quic, h3)", u.Scheme)
	}
	return d, nil
}

// nodeServerDomains — доменные имена серверов (их нужно резолвить напрямую).
func nodeServerDomains(s *model.Settings) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range s.Nodes {
		if n.Disabled || n.Server == "" || isIP(n.Server) || seen[n.Server] {
			continue
		}
		seen[n.Server] = true
		out = append(out, n.Server)
	}
	return out
}

func activeNodes(s *model.Settings) []model.Node {
	var out []model.Node
	for _, n := range s.Nodes {
		if !n.Disabled {
			out = append(out, n)
		}
	}
	return out
}

func hasTLS(n model.Node) bool {
	switch n.Type {
	case "trojan", "hysteria2", "tuic":
		return true
	}
	return n.TLS || n.Reality
}
