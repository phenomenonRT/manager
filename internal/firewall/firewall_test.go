package firewall

import (
	"os/exec"
	"strings"
	"testing"

	"corepanel/internal/model"
)

func baseSpec(mode, be string) *Spec {
	return &Spec{Mode: mode, Backend: be, RedirPort: 7892, TProxyPort: 7893, DNSPort: 1053,
		LANIfaces: []string{"br-lan"}, Include: []string{"192.168.1.50", "192.168.1.64/26"}, Exclude: []string{"192.168.1.10"},
		BypassDst: []string{"203.0.113.0/24"}, FwMark: 1, RouteTable: 100}
}

func TestNftRedirect(t *testing.T) {
	sc, err := Generate(baseSpec("redirect", "nft"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table ip corepanel", `iifname != { "br-lan" } return`, "fib daddr type local return",
		"ip saddr @skip_src return", "ip saddr != @only_src return", "redirect to :7892", "th dport 53 redirect to :1053", "203.0.113.0/24",
	} {
		if !strings.Contains(sc.Up, want) {
			t.Errorf("в nft-скрипте нет %q", want)
		}
	}
	if !strings.Contains(sc.Down, "nft delete table ip corepanel") {
		t.Error("нет снятия таблицы")
	}
	checkNft(t, sc.Up)
}

func TestNftTproxy(t *testing.T) {
	sc, _ := Generate(baseSpec("tproxy", "nft"))
	for _, want := range []string{"tproxy to :7893", "socket transparent 1", "ip rule add fwmark 1 lookup 100", "ip route replace local 0.0.0.0/0 dev lo table 100"} {
		if !strings.Contains(sc.Up, want) {
			t.Errorf("нет %q", want)
		}
	}
	if !strings.Contains(sc.Down, "ip rule del fwmark 1") {
		t.Error("tproxy: нет удаления ip rule")
	}
	checkNft(t, sc.Up)
}

func TestIptables(t *testing.T) {
	sc, _ := Generate(baseSpec("redirect", "iptables"))
	for _, want := range []string{
		"-t nat -N COREPANEL", "REDIRECT --to-ports 7892", "-i br-lan -s 192.168.1.50 -j COREPANEL",
		"-s 192.168.1.10 -j RETURN", "--dport 53 -j REDIRECT --to-ports 1053", "-d 203.0.113.0/24 -j RETURN",
	} {
		if !strings.Contains(sc.Up, want) {
			t.Errorf("нет %q\n%s", want, sc.Up)
		}
	}
	tp, _ := Generate(baseSpec("tproxy", "iptables"))
	if !strings.Contains(tp.Up, "-j TPROXY --on-port 7893 --tproxy-mark 0x1/0x1") {
		t.Error("нет TPROXY")
	}
	// каждая строка снятия должна быть безопасна под sh -e
	for _, l := range strings.Split(strings.TrimSpace(sc.Down), "\n") {
		if !strings.HasPrefix(l, "while ") && !strings.HasSuffix(l, "|| true") {
			t.Errorf("строка снятия может оборвать скрипт: %q", l)
		}
	}
}

func TestRejectsShellInjection(t *testing.T) {
	sp := baseSpec("redirect", "nft")
	sp.LANIfaces = []string{`br-lan"; rm -rf / #`}
	if _, err := Generate(sp); err == nil {
		t.Error("имя интерфейса с кавычками должно быть отклонено")
	}
	sp = baseSpec("redirect", "iptables")
	sp.Exclude = []string{"1.2.3.4; reboot"}
	if _, err := Generate(sp); err == nil {
		t.Error("мусор вместо IP должен быть отклонён")
	}
}

// checkNft проверяет синтаксис, если nft доступен и разрешён в песочнице.
func checkNft(t *testing.T, up string) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft не установлен")
	}
	start := strings.Index(up, "<<'COREPANEL_EOF'\n")
	end := strings.Index(up, "COREPANEL_EOF\n"+"")
	_ = end
	body := up[start+len("<<'COREPANEL_EOF'\n"):]
	body = body[:strings.Index(body, "COREPANEL_EOF")]
	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "Permission denied") {
			t.Skipf("nft -c недоступен в этой среде: %s", out)
		}
		t.Fatalf("nft -c: %v\n%s\n--- скрипт ---\n%s", err, out, body)
	}
}

func TestNftTProxyWithoutSocketModule(t *testing.T) {
	sp := baseSpec("tproxy", "nft")
	sp.NoSocketMatch = true
	sc, err := Generate(sp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sc.Up, "socket transparent") {
		t.Errorf("без nft_socket правило socket transparent выводиться не должно:\n%s", sc.Up)
	}
	if !strings.Contains(sc.Up, "tproxy to :7893") {
		t.Errorf("правило tproxy должно остаться:\n%s", sc.Up)
	}
}

func TestIfaceRoutes(t *testing.T) {
	s := model.Default()
	s.Ifaces = []model.Iface{{Name: "vpn1", Address: "172.20.1.1/30", Outbound: "x", Sources: []string{"192.168.1.50", "192.168.1.64/28", "evil; rm -rf /", "fe80::1"}}, {Name: "vpn2", Outbound: "x"}}
	sc := IfaceRoutes(s)
	if sc == nil {
		t.Fatal("nil")
	}
	for _, w := range []string{"ip route replace default dev vpn1 table 210", "ip rule add from 192.168.1.50/32 lookup 210", "ip rule add from 192.168.1.64/28 lookup 210"} {
		if !strings.Contains(sc.Up, w) {
			t.Fatalf("нет %q:\n%s", w, sc.Up)
		}
	}
	if strings.Contains(sc.Up, "evil") || strings.Contains(sc.Up, "fe80") || strings.Contains(sc.Up, "vpn2") {
		t.Fatalf("лишнее:\n%s", sc.Up)
	}
	if !strings.Contains(sc.Down, "ip rule del from 192.168.1.50/32 lookup 210") {
		t.Fatal(sc.Down)
	}
	s.Ifaces = nil
	if IfaceRoutes(s) != nil {
		t.Fatal("без интерфейсов скрипт не нужен")
	}
}

func TestTProxyNeedsMarkAndTable(t *testing.T) {
	s := model.Default()
	s.Firewall.Mode, s.Firewall.Backend, s.Firewall.FwMark = "tproxy", "nft", 0
	if _, err := FromSettings(s, "nft"); err == nil {
		t.Fatal("fwmark 0 дал бы «ip rule add fwmark 0» — должна быть ошибка")
	}
}

func TestBlockIPv6(t *testing.T) {
	s := model.Default()
	if BlockIPv6(s) != nil {
		t.Error("по умолчанию блокировки IPv6 быть не должно")
	}
	s.Tun.BlockIPv6 = true
	if BlockIPv6(s) != nil {
		t.Error("без включённого TUN блокировка не нужна")
	}
	s.Tun.Enabled = true
	sc := BlockIPv6(s)
	if sc == nil {
		t.Fatal("блокировка не построена")
	}
	if !strings.Contains(sc.Up, "/proc/sys/net/ipv6") {
		t.Errorf("up должен пропускать системы без IPv6: %q", sc.Up)
	}
	if !strings.Contains(sc.Up, "ip -6 route replace unreachable ::/0 metric 1") {
		t.Errorf("up: %q", sc.Up)
	}
	if !strings.Contains(sc.Down, "ip -6 route del unreachable ::/0 metric 1") || !strings.Contains(sc.Down, "|| true") {
		t.Errorf("down должен снимать маршрут и не падать, если его нет: %q", sc.Down)
	}
}

func TestNodeIfaceRoutes(t *testing.T) {
	s := model.Default()
	s.Nodes = []model.Node{{Name: "a", Type: "vless"}, {Name: "sstp", Type: "iface", BindInterface: "sstp-vpn0"}, {Name: "off", Type: "iface", BindInterface: "x0", Disabled: true}, {Name: "l2tp", Type: "iface", BindInterface: "l2tp0"}}
	sc := NodeIfaceRoutes(s)
	if sc == nil {
		t.Fatal("nil")
	}
	for _, w := range []string{
		"while ip rule del pref 10200", "while ip -6 rule del pref 10200",
		"if [ -d /sys/class/net/sstp-vpn0 ]",
		"ip route replace default dev sstp-vpn0 table 300",
		"ip -6 route replace default dev sstp-vpn0 table 300",
		"ip rule add oif sstp-vpn0 lookup 300 pref 10200",
		"ip -6 rule add oif sstp-vpn0 lookup 300 pref 10200",
		"ip route replace default dev l2tp0 table 301",
		"ip rule add oif l2tp0 lookup 301 pref 10201",
	} {
		if !strings.Contains(sc.Up, w) {
			t.Fatalf("нет %q:\n%s", w, sc.Up)
		}
	}
	if strings.Contains(sc.Up, "x0") {
		t.Fatalf("отключённый узел попал в up:\n%s", sc.Up)
	}
	// refresh не пересоздаёт правило вслепую: сначала проверяет, что оно есть и смотрит на то же устройство,
	// иначе после переподключения интерфейса правило указывало бы на старый индекс
	for _, w := range []string{
		"if [ -d /sys/class/net/sstp-vpn0 ]",
		"grep -qE '^10200:.*oif sstp-vpn0 '",
		"ip rule add oif sstp-vpn0 lookup 300 pref 10200",
		"ip route replace default dev l2tp0 table 301",
		"ip -6 rule add oif l2tp0 lookup 301 pref 10201",
	} {
		if !strings.Contains(sc.Refresh, w) {
			t.Fatalf("refresh: нет %q:\n%s", w, sc.Refresh)
		}
	}
	if strings.Contains(sc.Refresh, "x0") {
		t.Fatalf("отключённый узел попал в refresh:\n%s", sc.Refresh)
	}
	for _, w := range []string{"while ip rule del pref 10200", "while ip -6 rule del pref 10200", "ip route flush table 300", "ip -6 route flush table 300"} {
		if !strings.Contains(sc.Down, w) {
			t.Fatalf("down: нет %q:\n%s", w, sc.Down)
		}
	}
	s.Nodes = s.Nodes[:1]
	if NodeIfaceRoutes(s) != nil {
		t.Fatal("без узлов-интерфейсов скрипт не нужен")
	}
}
