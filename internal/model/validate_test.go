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

// Clash-API ядра отвечает «400 Bad Request» на timeout больше 32767 мс, поэтому предел панели — 30 с:
// иначе кнопка «Проверить задержку» показывала бы все узлы как «сбой», ничего не проверяя.
func TestGroupTimeoutRange(t *testing.T) {
	hasTimeoutErr := func(s *Settings) bool {
		for _, is := range s.Validate() {
			if strings.Contains(is.Message, "таймаут проверки") {
				return true
			}
		}
		return false
	}
	mk := func(ms int) *Settings {
		s := Default()
		s.Nodes = []Node{{Name: "a", Type: "socks", Server: "127.0.0.1", Port: 1080}}
		s.Groups = []Group{{Name: "g", Type: "urltest", Members: []string{"a"}, Timeout: ms}}
		return s
	}
	if hasTimeoutErr(mk(DelayTimeoutMax)) {
		t.Errorf("таймаут %d мс должен быть допустим (предел панели)", DelayTimeoutMax)
	}
	if !hasTimeoutErr(mk(DelayTimeoutMax + 1000)) {
		t.Errorf("таймаут %d мс должен отклоняться: ядро не принимает больше 32767 мс", DelayTimeoutMax+1000)
	}
	if hasTimeoutErr(mk(0)) {
		t.Error("таймаут 0 (значение по умолчанию) не должен давать ошибку")
	}
}

// Таймаут проверки можно задать и отдельному узлу (столбец «Таймаут, с» в «Узлы и VPN»):
// 0 — как у группы. Границы те же: ядро не принимает больше 30 с.
func TestNodeTimeoutRange(t *testing.T) {
	hasTimeoutErr := func(s *Settings) bool {
		for _, is := range s.Validate() {
			if strings.Contains(is.Message, "узел «a»") && strings.Contains(is.Message, "таймаут проверки") {
				return true
			}
		}
		return false
	}
	mk := func(ms int) *Settings {
		s := Default()
		s.Nodes = []Node{{Name: "a", Type: "socks", Server: "127.0.0.1", Port: 1080, Timeout: ms}}
		s.Groups = []Group{{Name: "g", Type: "urltest", Members: []string{"a"}}}
		return s
	}
	if hasTimeoutErr(mk(DelayTimeoutMax)) {
		t.Errorf("таймаут узла %d мс должен быть допустим", DelayTimeoutMax)
	}
	if !hasTimeoutErr(mk(DelayTimeoutMax + 1000)) {
		t.Errorf("таймаут узла %d мс должен отклоняться: ядро не принимает больше 32767 мс", DelayTimeoutMax+1000)
	}
	if hasTimeoutErr(mk(0)) {
		t.Error("таймаут узла 0 (как у группы) не должен давать ошибку")
	}
}

// Ограничение памяти ядра (GOMEMLIMIT): 0 — без ограничения, иначе 32–4096 МБ.
func TestMemLimitRange(t *testing.T) {
	hasErr := func(s *Settings) bool {
		for _, is := range s.Validate() {
			if strings.Contains(is.Message, "ограничение памяти ядра") {
				return true
			}
		}
		return false
	}
	mk := func(mb int) *Settings {
		s := Default()
		s.General.MemLimitMB = mb
		return s
	}
	if hasErr(mk(0)) {
		t.Error("0 (без ограничения) не должен давать ошибку")
	}
	if hasErr(mk(128)) {
		t.Error("128 МБ должен быть допустим")
	}
	if hasErr(mk(MemLimitMaxMB)) {
		t.Errorf("%d МБ должен быть допустим", MemLimitMaxMB)
	}
	if !hasErr(mk(MemLimitMinMB - 1)) {
		t.Error("меньше минимума — должно отклоняться")
	}
	if !hasErr(mk(MemLimitMaxMB + 1)) {
		t.Errorf("больше %d МБ — должно отклоняться", MemLimitMaxMB)
	}
}
