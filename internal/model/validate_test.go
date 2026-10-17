package model

import (
	"strings"
	"testing"
)

// Таблицы панели (210+N под «свои» интерфейсы и 300+N под узлы-интерфейсы) и таблица tproxy не должны
// совпадать: помеченные ядром пакеты ушли бы в VPN вместо «local dev lo» и маршрутизация молча сломалась бы.
func TestTProxyRouteTableCollision(t *testing.T) {
	hasCollision := func(s *Settings) bool {
		for _, is := range s.Validate() {
			if strings.Contains(is.Message, "занята панелью") {
				return true
			}
		}
		return false
	}

	s := Default()
	s.Nodes = []Node{{Name: "t", Type: "iface", BindInterface: "sstp-vpn0"}}
	s.Firewall.Mode, s.Firewall.RouteTable = "tproxy", 300
	if !hasCollision(s) {
		t.Error("таблица 300 занята узлом-интерфейсом — ждали ошибку")
	}
	s.Firewall.RouteTable = 100
	if hasCollision(s) {
		t.Error("таблица 100 свободна — ошибки быть не должно")
	}

	s = Default()
	s.Ifaces = []Iface{{Name: "vpn1", Address: "172.20.1.1/30", Outbound: "direct", Sources: []string{"192.168.1.50"}}}
	s.Firewall.Mode, s.Firewall.RouteTable = "tproxy", 210
	if !hasCollision(s) {
		t.Error("таблица 210 занята интерфейсом панели — ждали ошибку")
	}
	s.Firewall.Mode = "redirect"
	if hasCollision(s) {
		t.Error("в режиме redirect таблица маршрутизации не используется — ошибки быть не должно")
	}
}
