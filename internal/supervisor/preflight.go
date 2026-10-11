package supervisor

import (
	"net"
	"os"
	"strconv"
	"strings"

	"corepanel/internal/model"
)

// hasDefaultRoute разбирает содержимое /proc/net/route: есть ли активный маршрут по умолчанию.
func hasDefaultRoute(route string) bool {
	for i, l := range strings.Split(route, "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 4 {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if f[1] == "00000000" && err == nil && flags&1 != 0 {
			return true
		}
	}
	return false
}

// preflight проверяет, готова ли система к запуску. Возвращает причины ожидания и признак того,
// что без этого ядро точно не стартует (нет маршрута в интернет для WireGuard/AmneziaWG).
func preflight(set *model.Settings) (reasons []string, hard bool) {
	vpn := false
	for _, n := range set.Nodes {
		if n.Disabled {
			continue
		}
		switch n.Type {
		case "wireguard", "awg":
			vpn = true
		case "iface":
			if n.BindInterface == "" {
				continue
			}
			if ifc, err := net.InterfaceByName(n.BindInterface); err != nil || ifc.Flags&net.FlagUp == 0 {
				reasons = append(reasons, "интерфейс «"+n.BindInterface+"» ещё не поднят")
			}
		}
	}
	if vpn {
		if b, err := os.ReadFile("/proc/net/route"); err == nil && !hasDefaultRoute(string(b)) {
			reasons = append(reasons, "нет маршрута в интернет (WAN не поднялся)")
			hard = true
		}
	}
	return reasons, hard
}
