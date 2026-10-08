package firewall

import (
	"os/exec"
	"strings"
	"testing"
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
