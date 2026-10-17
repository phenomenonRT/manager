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
	// NoSocketMatch — не выводить правило «socket transparent» (nftables): на роутере нет модуля
	// nft_socket (kmod-nft-socket). Правило лишь ускоряет уже установленные TCP-соединения;
	// ядро tproxy само находит их сокеты, так что без него всё работает.
	NoSocketMatch bool
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
	if be == "nft" && sp.Mode == "tproxy" {
		sp.NoSocketMatch = !nftSocketSupported()
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
	if sp.Mode == "tproxy" && (sp.FwMark <= 0 || sp.RouteTable <= 0) {
		return fmt.Errorf("для tproxy задайте fwmark и номер таблицы маршрутизации (больше 0)")
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
	Up      string `json:"up"`
	Down    string `json:"down"`
	Refresh string `json:"-"` // повторное создание маршрутов (они исчезают, когда интерфейс переподключается)
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
		if !sp.NoSocketMatch {
			fmt.Fprintf(&b, "\t\tmeta l4proto tcp socket transparent 1 meta mark set %d accept\n", sp.FwMark)
		}
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

// nftSocketSupported проверяет, понимает ли ядро выражение «socket» в nftables (модуль nft_socket).
// Проба идёт в режиме проверки (-c): правила не применяются, но ядро подгружает модуль или отказывает.
func nftSocketSupported() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader("table ip corepanel_probe {\n\tchain c {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n\t\tmeta l4proto tcp socket transparent 1 accept\n\t}\n}\n")
	return cmd.Run() == nil
}

// BlockIPv6 строит скрипты блокировки IPv6: маршрут «unreachable ::/0» с наименьшей метрикой перекрывает
// маршрут по умолчанию от провайдера, а более специфичные маршруты (LAN, link-local) продолжают работать.
// Клиенты сразу получают ICMP «недостижимо» и переходят на IPv4. Возвращает nil, если блокировка не нужна.
func BlockIPv6(s *model.Settings) *Scripts {
	if !s.Tun.Enabled || !s.Tun.BlockIPv6 {
		return nil
	}
	return &Scripts{
		Up: "[ -d /proc/sys/net/ipv6 ] || exit 0\n" + // в ядре нет IPv6 — блокировать нечего
			"ip -6 route replace unreachable ::/0 metric 1\n",
		Down: "ip -6 route del unreachable ::/0 metric 1 2>/dev/null || true\n",
	}
}

// IfaceRoutes строит скрипты, которые направляют устройства LAN в свои TUN-интерфейсы: отдельная таблица
// маршрутов на интерфейс и правила «from источник». Скрипты идемпотентны и переживают пересоздание
// устройства: пока его нет, они ничего не делают, а Refresh возвращает маршрут и правила, если пропали.
// Возвращает nil, если направлять нечего.
func IfaceRoutes(s *model.Settings) *Scripts {
	var up, down, refresh strings.Builder
	n := 0
	for i, f := range s.Ifaces {
		if f.Disabled || f.Name == "" {
			continue
		}
		var srcs []string
		for _, src := range f.Sources {
			src = strings.TrimSpace(src)
			if ip := net.ParseIP(src); ip != nil && ip.To4() != nil {
				srcs = append(srcs, src+"/32")
			} else if _, nw, err := net.ParseCIDR(src); err == nil && nw.IP.To4() != nil {
				srcs = append(srcs, nw.String())
			}
		}
		if len(srcs) == 0 {
			continue
		}
		n++
		table, pref := 210+i, 10000+i
		snippet := ifaceSourceSnippet(f.Name, table, pref, srcs)
		refresh.WriteString(snippet)
		// устройство создаёт ядро чуть позже запуска панели — коротко ждём его, чтобы не откладывать маршруты
		fmt.Fprintf(&up, "for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do ip link show %s >/dev/null 2>&1 && break; sleep 0.5; done\n", f.Name)
		up.WriteString(snippet)
		for _, src := range srcs {
			fmt.Fprintf(&down, "while ip rule del pref %d from %s 2>/dev/null; do :; done\n", pref, src)
		}
		fmt.Fprintf(&down, "ip route flush table %d\n", table)
	}
	if n == 0 {
		return nil
	}
	return &Scripts{Up: up.String(), Down: tolerant(down.String()), Refresh: refresh.String()}
}

// ifaceSourceSnippet — идемпотентный рецепт для «своего» интерфейса панели: пока устройства нет, ничего не
// делаем; маршрут в таблице и правила «from источник» восстанавливаются, если пропали после пересоздания
// устройства. Правило ищется по приоритету, источнику и таблице — существующее не пересоздаётся.
func ifaceSourceSnippet(iface string, table, pref int, srcs []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "if [ -d /sys/class/net/%s ]; then\n", iface)
	fmt.Fprintf(&b, "ip route replace default dev %s table %d 2>/dev/null || true\n", iface, table)
	for _, src := range srcs {
		patt := ruleSrcRe(src)
		check := fmt.Sprintf("grep -qE '^%d:.*from %s .*lookup %d([^0-9]|$)'", pref, patt, table)
		fmt.Fprintf(&b, "ip rule show pref %d 2>/dev/null | %s || ip rule show 2>/dev/null | %s || "+
			"{ while ip rule del pref %d from %s 2>/dev/null; do :; done; "+
			"ip rule add from %s lookup %d pref %d 2>/dev/null || true; }\n",
			pref, check, check, pref, src, src, table, pref)
	}
	b.WriteString("fi\n")
	return b.String()
}

// ruleSrcRe — как «from источник» выглядит в выводе ip rule show: у одиночного адреса маску /32 обычно не
// печатают, поэтому она допускается необязательной.
func ruleSrcRe(src string) string {
	if bare := strings.TrimSuffix(src, "/32"); bare != src {
		return regexp.QuoteMeta(bare) + "(/32)?"
	}
	return regexp.QuoteMeta(src)
}

// NodeIfaceRoutes строит маршруты для узлов «Системный VPN (интерфейс)»: пакеты, привязанные к интерфейсу
// (bind_interface), уходят своей таблицей в нужный интерфейс правилом «oif» — без меток, чтобы не мешать TUN
// с auto_redirect. Скрипты переживают отсутствие интерфейса и его пересоздание: пока интерфейса нет, они ничего
// не делают, а Refresh возвращает правило, даже если оно указывает на старый индекс устройства.
// Возвращает nil, если таких узлов нет.
func NodeIfaceRoutes(s *model.Settings) *Scripts {
	var up, down, refresh strings.Builder
	n := 0
	for _, nd := range s.Nodes {
		slot := s.IfaceNodeSlot(nd.Name)
		if nd.Type != "iface" || slot < 0 || !ifaceRe.MatchString(nd.BindInterface) {
			continue
		}
		n++
		table, pref := model.IfaceNodeTableBase+slot, model.IfaceNodePrefBase+slot
		snippet := ifaceRouteSnippet(nd.BindInterface, table, pref)
		refresh.WriteString(snippet)
		// по приоритету удаляем и правила старых версий панели (они были по метке), затем применяем маршруты
		fmt.Fprintf(&up, "while ip rule del pref %d 2>/dev/null; do :; done\n", pref)
		fmt.Fprintf(&up, "while ip -6 rule del pref %d 2>/dev/null; do :; done\n", pref)
		up.WriteString(snippet)
		fmt.Fprintf(&down, "while ip rule del pref %d 2>/dev/null; do :; done\n", pref)
		fmt.Fprintf(&down, "while ip -6 rule del pref %d 2>/dev/null; do :; done\n", pref)
		fmt.Fprintf(&down, "ip route flush table %d 2>/dev/null\n", table)
		fmt.Fprintf(&down, "ip -6 route flush table %d 2>/dev/null\n", table)
	}
	if n == 0 {
		return nil
	}
	return &Scripts{Up: up.String(), Down: tolerant(down.String()), Refresh: refresh.String()}
}

// ifaceRouteSnippet — идемпотентный рецепт маршрута через интерфейс: выполняется, только если интерфейс
// существует (иначе применялся бы к чужому устройству); правило «oif» пересоздаётся, если пропало,
// смотрит не на тот интерфейс или не в ту таблицу — так оно обновляется после пересоздания устройства.
func ifaceRouteSnippet(iface string, table, pref int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "if [ -d /sys/class/net/%s ]; then\n", iface)
	fmt.Fprintf(&b, "ip route replace default dev %s table %d 2>/dev/null || true\n", iface, table)
	fmt.Fprintf(&b, "ip -6 route replace default dev %s table %d 2>/dev/null || true\n", iface, table)
	for _, ip := range []string{"ip", "ip -6"} {
		fmt.Fprintf(&b, "%s rule show pref %d 2>/dev/null | grep -qE '^%d:.*oif %s .*lookup %d([^0-9]|$)' || "+
			"{ while %s rule del pref %d 2>/dev/null; do :; done; %s rule add oif %s lookup %d pref %d 2>/dev/null || true; }\n",
			ip, pref, pref, regexp.QuoteMeta(iface), table, ip, pref, ip, iface, table, pref)
	}
	b.WriteString("fi\n")
	return b.String()
}

// Refresh повторно применяет маршруты узлов-интерфейсов (ошибки игнорируются).
func (sc *Scripts) RunRefresh(ctx context.Context) {
	if sc != nil && sc.Refresh != "" {
		_, _ = run(ctx, sc.Refresh)
	}
}

// NodeIfaceCheck — фактическое состояние маршрута узла-интерфейса в системе. Панель показывает его в
// диагностике, чтобы отличить «правило панели пропало» от «туннель не отвечает».
type NodeIfaceCheck struct {
	Node  string `json:"node"`
	Iface string `json:"iface"`
	Table int    `json:"table"`
	Pref  int    `json:"pref"`
	Rule  bool   `json:"rule"`           // правило «oif <интерфейс>» с нужным приоритетом есть в системе
	Route bool   `json:"route"`          // в таблице есть маршрут по умолчанию через этот интерфейс
	Tool  string `json:"tool,omitempty"` // "busybox" — системный ip не умеет правила «oif»: нужен iproute2 (ip-full)
	Out   string `json:"out,omitempty"`  // что ответила система, если правила или маршрута не хватает
}

// CheckNodeIfaceRoutes проверяет, что маршруты узлов-интерфейсов действительно стоят в системе.
func CheckNodeIfaceRoutes(s *model.Settings) []NodeIfaceCheck {
	out := []NodeIfaceCheck{}
	ipTool, ipToolDone := "", false
	// busybox спрашиваем один раз и только когда правило действительно отсутствует
	ipIsBusybox := func() bool {
		if !ipToolDone {
			ipToolDone = true
			if busyboxIP() {
				ipTool = "busybox"
			}
		}
		return ipTool == "busybox"
	}
	for _, nd := range s.Nodes {
		slot := s.IfaceNodeSlot(nd.Name)
		if nd.Type != "iface" || slot < 0 || !ifaceRe.MatchString(nd.BindInterface) {
			continue
		}
		c := NodeIfaceCheck{Node: nd.Name, Iface: nd.BindInterface,
			Table: model.IfaceNodeTableBase + slot, Pref: model.IfaceNodePrefBase + slot}
		var ruleOut, routeOut string
		c.Rule, ruleOut = ifaceRulePresent(nd.BindInterface, c.Pref)
		c.Route, routeOut = ifaceRoutePresent(nd.BindInterface, c.Table)
		if !c.Rule && ipIsBusybox() {
			c.Tool = "busybox"
		}
		if !c.Rule || !c.Route {
			clip := func(v string) string {
				v = strings.TrimSpace(v)
				if v == "" {
					v = "(пусто)"
				}
				if len(v) > 300 {
					v = v[:300] + "…"
				}
				return v
			}
			parts := []string{}
			if !c.Rule {
				parts = append(parts, fmt.Sprintf("ip rule show pref %d -> %s", c.Pref, clip(ruleOut)))
			}
			if !c.Route {
				parts = append(parts, fmt.Sprintf("ip route show table %d -> %s", c.Table, clip(routeOut)))
			}
			c.Out = strings.Join(parts, "\n")
		}
		out = append(out, c)
	}
	return out
}

// ifaceRulePresent ищет правило «oif» с нужным приоритетом. Имя интерфейса сверяется как есть: правило
// со старым индексом устройства после его пересоздания выводится как «oif if7» и считается пропавшим.
func ifaceRulePresent(iface string, pref int) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// у busybox-ip нет выбора по приоритету: тогда разбираем полный список
	script := fmt.Sprintf("ip rule show pref %d 2>/dev/null || ip rule show 2>/dev/null", pref)
	out, err := run(ctx, script)
	if err != nil && out == "" {
		return false, ""
	}
	want, needle := fmt.Sprintf("%d:", pref), "oif "+iface+" "
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, want) && strings.Contains(l, needle) {
			return true, ""
		}
	}
	return false, out
}

// ifaceRoutePresent ищет в таблице узла маршрут по умолчанию через его интерфейс.
func ifaceRoutePresent(iface string, table int) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := run(ctx, fmt.Sprintf("ip route show table %d 2>/dev/null || true", table))
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "default") && strings.Contains(l, " dev "+iface) {
			return true, ""
		}
	}
	return false, out
}

// busyboxIP сообщает, что системный ip — из busybox (или ip не установлен вовсе): такой ip не умеет
// правила «oif», поэтому для узлов-интерфейсов нужен iproute2 — на OpenWrt это пакет ip-full.
func busyboxIP() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := run(ctx, "ip -V 2>&1 || true")
	return !strings.Contains(out, "iproute2")
}
