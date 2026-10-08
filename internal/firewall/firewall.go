// Package firewall генерирует и применяет правила прозрачного проксирования
// для режимов redirect и tproxy: nftables (OpenWrt) или iptables (Keenetic/Entware).
package firewall

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"corepanel/internal/model"
)

// Spec — параметры правил.
type Spec struct {
	Mode       string // redirect | tproxy
	Backend    string // nft | iptables
	RedirPort  int
	TProxyPort int
	DNSPort    int // 0 — не перехватывать DNS
	LANIfaces  []string
	Include    []string
	Exclude    []string
	BypassDst  []string
	FwMark     int
	RouteTable int
}

var ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.+-]{1,15}$`)

// bypassV4 — адреса назначения, которые никогда не проксируются.
var bypassV4 = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
}

// FromSettings строит Spec. backend — результат platform.Info.FirewallBE.
func FromSettings(s *model.Settings, backend string) (*Spec, error) {
	if s.Firewall.Mode != "redirect" && s.Firewall.Mode != "tproxy" {
		return nil, nil
	}
	be := s.Firewall.Backend
	if be == "" || be == "auto" {
		be = backend
	}
	if be != "nft" && be != "iptables" {
		return nil, fmt.Errorf("в системе нет nft или iptables — режим %s недоступен", s.Firewall.Mode)
	}
	sp := &Spec{
		Mode: s.Firewall.Mode, Backend: be,
		RedirPort: s.Inbounds.RedirPort, TProxyPort: s.Inbounds.TProxyPort,
		LANIfaces: s.Firewall.LANIfaces, Include: s.Firewall.Include, Exclude: s.Firewall.Exclude,
		BypassDst: s.Firewall.BypassDst, FwMark: s.Firewall.FwMark, RouteTable: s.Firewall.RouteTable,
	}
	if s.Firewall.DNSRedirect && s.DNS.Enabled {
		h, p := hostPort(s.DNS.Listen)
		if p == 0 {
			return nil, fmt.Errorf("для перехвата DNS задайте адрес DNS-слушателя вида 0.0.0.0:1053")
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			return nil, fmt.Errorf("для перехвата DNS ядро должно слушать не на 127.0.0.1, а на 0.0.0.0:%d", p)
		}
		sp.DNSPort = p
	}
	return sp, sp.validate()
}

func hostPort(a string) (string, int) {
	h, ps, err := net.SplitHostPort(a)
	if err != nil {
		return a, 0
	}
	var p int
	fmt.Sscanf(ps, "%d", &p)
	return h, p
}

func (sp *Spec) validate() error {
	for _, i := range sp.LANIfaces {
		if !ifaceRe.MatchString(i) {
			return fmt.Errorf("недопустимое имя интерфейса «%s»", i)
		}
	}
	for _, list := range [][]string{sp.Include, sp.Exclude, sp.BypassDst} {
		for _, c := range list {
			if !isV4(c) {
				if net.ParseIP(c) != nil || strings.Contains(c, ":") {
					continue // IPv6 в правила не попадает
				}
				return fmt.Errorf("«%s» — не IPv4-адрес и не подсеть", c)
			}
		}
	}
	if sp.Mode == "redirect" && sp.RedirPort <= 0 || sp.Mode == "tproxy" && sp.TProxyPort <= 0 {
		return fmt.Errorf("не задан порт для режима %s", sp.Mode)
	}
	return nil
}

func isV4(c string) bool {
	if ip := net.ParseIP(c); ip != nil {
		return ip.To4() != nil
	}
	ip, _, err := net.ParseCIDR(c)
	return err == nil && ip.To4() != nil
}

func v4only(list []string) []string {
	var out []string
	for _, c := range list {
		if isV4(c) {
			out = append(out, c)
		}
	}
	return out
}

// Scripts — готовые скрипты включения и отключения.
type Scripts struct {
	Up   string `json:"up"`
	Down string `json:"down"`
}

// Generate строит скрипты.
func Generate(sp *Spec) (*Scripts, error) {
	if err := sp.validate(); err != nil {
		return nil, err
	}
	if sp.Backend == "nft" {
		return genNft(sp), nil
	}
	return genIptables(sp), nil
}

// ---------- nftables ----------

func quoteList(l []string) string {
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = `"` + s + `"`
	}
	return strings.Join(q, ", ")
}

func genNft(sp *Spec) *Scripts {
	include, exclude := v4only(sp.Include), v4only(sp.Exclude)
	bypass := append(append([]string(nil), bypassV4...), v4only(sp.BypassDst)...)

	var b strings.Builder
	b.WriteString("table ip corepanel {\n")
	fmt.Fprintf(&b, "\tset bypass { type ipv4_addr; flags interval; auto-merge; elements = { %s } }\n", strings.Join(bypass, ", "))
	if len(include) > 0 {
		fmt.Fprintf(&b, "\tset only_src { type ipv4_addr; flags interval; auto-merge; elements = { %s } }\n", strings.Join(include, ", "))
	}
	if len(exclude) > 0 {
		fmt.Fprintf(&b, "\tset skip_src { type ipv4_addr; flags interval; auto-merge; elements = { %s } }\n", strings.Join(exclude, ", "))
	}
	common := func(b *strings.Builder) {
		if len(sp.LANIfaces) > 0 {
			fmt.Fprintf(b, "\t\tiifname != { %s } return\n", quoteList(sp.LANIfaces))
		}
		b.WriteString("\t\tfib daddr type local return\n")
		if len(exclude) > 0 {
			b.WriteString("\t\tip saddr @skip_src return\n")
		}
		if len(include) > 0 {
			b.WriteString("\t\tip saddr != @only_src return\n")
		}
	}
	if sp.DNSPort > 0 {
		b.WriteString("\tchain dns_nat {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
		common(&b)
		fmt.Fprintf(&b, "\t\tmeta l4proto { tcp, udp } th dport 53 redirect to :%d\n\t}\n", sp.DNSPort)
	}
	if sp.Mode == "redirect" {
		b.WriteString("\tchain proxy_nat {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
		common(&b)
		b.WriteString("\t\tip daddr @bypass return\n")
		fmt.Fprintf(&b, "\t\tmeta l4proto tcp redirect to :%d\n\t}\n", sp.RedirPort)
	} else {
		b.WriteString("\tchain proxy_mangle {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n")
		common(&b)
		b.WriteString("\t\tip daddr @bypass return\n")
		fmt.Fprintf(&b, "\t\tmeta l4proto tcp socket transparent 1 meta mark set %d accept\n", sp.FwMark)
		fmt.Fprintf(&b, "\t\tmeta l4proto { tcp, udp } tproxy to :%d meta mark set %d accept\n\t}\n", sp.TProxyPort, sp.FwMark)
	}
	b.WriteString("}\n")

	down := "nft delete table ip corepanel 2>/dev/null\n"
	var up strings.Builder
	up.WriteString("# corepanel: включение прозрачного проксирования (nftables)\n")
	up.WriteString(tolerant(down))
	up.WriteString("nft -f - <<'COREPANEL_EOF'\n" + b.String() + "COREPANEL_EOF\n")
	if sp.Mode == "tproxy" {
		fmt.Fprintf(&up, "ip rule add fwmark %d lookup %d 2>/dev/null\n", sp.FwMark, sp.RouteTable)
		fmt.Fprintf(&up, "ip route replace local 0.0.0.0/0 dev lo table %d\n", sp.RouteTable)
		down += fmt.Sprintf("ip rule del fwmark %d lookup %d 2>/dev/null\nip route del local 0.0.0.0/0 dev lo table %d 2>/dev/null\n", sp.FwMark, sp.RouteTable, sp.RouteTable)
	}
	return &Scripts{Up: up.String(), Down: tolerant(down)}
}

// tolerant добавляет «|| true» к командам снятия правил, чтобы отсутствие
// правил не считалось ошибкой при запуске с sh -e.
func tolerant(script string) string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(script, "\n"), "\n") {
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "while ") {
			out = append(out, l)
			continue
		}
		out = append(out, l+" || true")
	}
	return strings.Join(out, "\n") + "\n"
}

// ---------- iptables ----------

func genIptables(sp *Spec) *Scripts {
	include, exclude := v4only(sp.Include), v4only(sp.Exclude)
	bypass := append(append([]string(nil), bypassV4...), v4only(sp.BypassDst)...)
	const chain, dnsChain = "COREPANEL", "COREPANEL_DNS"

	// хуки в PREROUTING: по интерфейсам × источникам
	type hook struct{ iface, src string }
	var hooks []hook
	ifaces := sp.LANIfaces
	if len(ifaces) == 0 {
		ifaces = []string{""}
	}
	srcs := include
	if len(srcs) == 0 {
		srcs = []string{""}
	}
	for _, i := range ifaces {
		for _, s := range srcs {
			hooks = append(hooks, hook{i, s})
		}
	}
	hookArgs := func(h hook) string {
		a := ""
		if h.iface != "" {
			a += " -i " + h.iface
		}
		if h.src != "" {
			a += " -s " + h.src
		}
		return a
	}
	table := "nat"
	if sp.Mode == "tproxy" {
		table = "mangle"
	}

	var up, down strings.Builder
	// ---- снятие ----
	for _, h := range hooks {
		fmt.Fprintf(&down, "while iptables -t %s -D PREROUTING%s -j %s 2>/dev/null; do :; done\n", table, hookArgs(h), chain)
		if sp.DNSPort > 0 {
			fmt.Fprintf(&down, "while iptables -t nat -D PREROUTING%s -j %s 2>/dev/null; do :; done\n", hookArgs(h), dnsChain)
		}
	}
	fmt.Fprintf(&down, "iptables -t %s -F %s 2>/dev/null\niptables -t %s -X %s 2>/dev/null\n", table, chain, table, chain)
	fmt.Fprintf(&down, "iptables -t nat -F %s 2>/dev/null\niptables -t nat -X %s 2>/dev/null\n", dnsChain, dnsChain)
	if sp.Mode == "tproxy" {
		fmt.Fprintf(&down, "ip rule del fwmark %d lookup %d 2>/dev/null\nip route del local 0.0.0.0/0 dev lo table %d 2>/dev/null\n", sp.FwMark, sp.RouteTable, sp.RouteTable)
	}

	// ---- включение ----
	up.WriteString("# corepanel: включение прозрачного проксирования (iptables)\n")
	up.WriteString(tolerant(down.String()))
	skip := func(t, c string) {
		fmt.Fprintf(&up, "iptables -t %s -A %s -m addrtype --dst-type LOCAL -j RETURN\n", t, c)
		for _, e := range exclude {
			fmt.Fprintf(&up, "iptables -t %s -A %s -s %s -j RETURN\n", t, c, e)
		}
	}
	if sp.DNSPort > 0 {
		fmt.Fprintf(&up, "iptables -t nat -N %s\n", dnsChain)
		skip("nat", dnsChain)
		fmt.Fprintf(&up, "iptables -t nat -A %s -p udp --dport 53 -j REDIRECT --to-ports %d\n", dnsChain, sp.DNSPort)
		fmt.Fprintf(&up, "iptables -t nat -A %s -p tcp --dport 53 -j REDIRECT --to-ports %d\n", dnsChain, sp.DNSPort)
		for _, h := range hooks {
			fmt.Fprintf(&up, "iptables -t nat -I PREROUTING%s -j %s\n", hookArgs(h), dnsChain)
		}
	}
	fmt.Fprintf(&up, "iptables -t %s -N %s\n", table, chain)
	skip(table, chain)
	for _, c := range bypass {
		fmt.Fprintf(&up, "iptables -t %s -A %s -d %s -j RETURN\n", table, chain, c)
	}
	if sp.Mode == "redirect" {
		fmt.Fprintf(&up, "iptables -t nat -A %s -p tcp -j REDIRECT --to-ports %d\n", chain, sp.RedirPort)
	} else {
		fmt.Fprintf(&up, "iptables -t mangle -A %s -p tcp -j TPROXY --on-port %d --tproxy-mark 0x%x/0x%x\n", chain, sp.TProxyPort, sp.FwMark, sp.FwMark)
		fmt.Fprintf(&up, "iptables -t mangle -A %s -p udp -j TPROXY --on-port %d --tproxy-mark 0x%x/0x%x\n", chain, sp.TProxyPort, sp.FwMark, sp.FwMark)
	}
	for _, h := range hooks {
		fmt.Fprintf(&up, "iptables -t %s -I PREROUTING%s -j %s\n", table, hookArgs(h), chain)
	}
	if sp.Mode == "tproxy" {
		fmt.Fprintf(&up, "ip rule add fwmark %d lookup %d 2>/dev/null\n", sp.FwMark, sp.RouteTable)
		fmt.Fprintf(&up, "ip route replace local 0.0.0.0/0 dev lo table %d\n", sp.RouteTable)
	}
	return &Scripts{Up: up.String(), Down: tolerant(down.String())}
}

// ---------- применение ----------

func run(ctx context.Context, script string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-e")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Apply применяет скрипт включения.
func Apply(ctx context.Context, sc *Scripts) error {
	if out, err := run(ctx, sc.Up); err != nil {
		_, _ = run(ctx, sc.Down)
		return fmt.Errorf("не удалось применить правила: %v: %s", err, out)
	}
	return nil
}

// Remove снимает правила (ошибки игнорируются: правил может не быть).
func Remove(ctx context.Context, sc *Scripts) {
	if sc != nil {
		_, _ = run(ctx, sc.Down)
	}
}
