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

// Обновление панели не должно «замораживать» конфиг из-за старых значений: Normalize приводит
// сохранённый таймаут (до 0.1.68 допускались 60 с) к рабочему диапазону.
func TestNormalizeClampsTimeouts(t *testing.T) {
	s := Default()
	s.Nodes = []Node{{Name: "a", Type: "socks", Server: "127.0.0.1", Port: 1080}}
	s.Groups = []Group{{Name: "g", Type: "urltest", Members: []string{"a"}, Timeout: 60000}}
	s.Normalize()
	if s.Groups[0].Timeout != DelayTimeoutMax {
		t.Errorf("таймаут группы 60 с должен стать %d мс, получено %d", DelayTimeoutMax, s.Groups[0].Timeout)
	}
	s2 := Default()
	s2.Groups = []Group{{Name: "g", Type: "urltest", Members: []string{"direct"}, Timeout: 200}}
	s2.Normalize()
	if s2.Groups[0].Timeout != DelayTimeoutMin {
		t.Errorf("слишком малый таймаут должен стать %d мс, получено %d", DelayTimeoutMin, s2.Groups[0].Timeout)
	}
	if issues := s.Validate(); len(issues) > 0 {
		for _, is := range issues {
			if is.Level == "error" && strings.Contains(is.Message, "таймаут проверки") {
				t.Errorf("после Normalize не должно быть ошибок про таймаут: %s", is.Message)
			}
		}
	}
}
