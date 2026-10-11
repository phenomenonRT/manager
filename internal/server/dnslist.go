package server

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// systemResolver — DNS-сервер, найденный в системе роутера.
type systemResolver struct {
	Addr   string `json:"addr"`
	Source string `json:"source"`
}

// parseResolvConf достаёт адреса из строк «nameserver X» (кроме loopback и пустых).
func parseResolvConf(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a := f[1]
		if i := strings.Index(a, "%"); i >= 0 { // fe80::1%br-lan
			a = a[:i]
		}
		ip := net.ParseIP(a)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		out = append(out, a)
	}
	return out
}

// dnsSystem отдаёт DNS-серверы, которые роутер получил от провайдера или прописал сам.
func (s *Server) dnsSystem(w http.ResponseWriter, r *http.Request) {
	files := []struct{ path, source string }{
		{"/tmp/resolv.conf.d/resolv.conf.auto", "получен от провайдера (WAN)"},
		{"/tmp/resolv.conf.auto", "получен от провайдера (WAN)"},
		{"/etc/resolv.conf", "системный"},
		{"/opt/etc/resolv.conf", "системный (Entware)"},
	}
	seen := map[string]bool{}
	out := []systemResolver{}
	for _, f := range files {
		b, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		for _, a := range parseResolvConf(string(b)) {
			if !seen[a] {
				seen[a] = true
				out = append(out, systemResolver{Addr: a, Source: f.source})
			}
		}
	}
	ok(w, out)
}
