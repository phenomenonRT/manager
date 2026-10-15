// Package dnstest отправляет тестовый DNS-запрос на выбранный сервер (UDP, TCP, DoT, DoH) и измеряет время ответа.
// Проверка идёт с самого роутера напрямую, поэтому показывает, доступен ли сервер из сети провайдера.
package dnstest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Result — итог проверки.
type Result struct {
	OK    bool     `json:"ok"`
	Ms    int      `json:"ms"`
	Proto string   `json:"proto"`
	IPs   []string `json:"ips,omitempty"`
	Error string   `json:"error,omitempty"`
}

const testName = "example.com"

var rcodes = map[int]string{1: "ошибка формата", 2: "сбой сервера", 3: "имя не найдено", 4: "не реализовано", 5: "отказ (REFUSED)"}

func buildQuery() []byte {
	var id [2]byte
	_, _ = rand.Read(id[:])
	b := []byte{id[0], id[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(testName, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, 0, 1, 0, 1) // тип A, класс IN
}

func skipName(m []byte, i int) (int, bool) {
	for i < len(m) {
		l := int(m[i])
		switch {
		case l == 0:
			return i + 1, true
		case l&0xC0 == 0xC0:
			return i + 2, i+2 <= len(m)
		default:
			i += l + 1
		}
	}
	return 0, false
}

// parse проверяет ответ и возвращает найденные IPv4-адреса.
func parse(q, m []byte) ([]string, error) {
	if len(m) < 12 {
		return nil, errors.New("слишком короткий ответ")
	}
	if m[0] != q[0] || m[1] != q[1] {
		return nil, errors.New("ответ на другой запрос")
	}
	if m[2]&0x80 == 0 {
		return nil, errors.New("это не ответ DNS")
	}
	if rc := int(m[3] & 0x0F); rc != 0 {
		if t, ok := rcodes[rc]; ok {
			return nil, errors.New("сервер ответил: " + t)
		}
		return nil, fmt.Errorf("сервер ответил кодом %d", rc)
	}
	qd, an := int(binary.BigEndian.Uint16(m[4:])), int(binary.BigEndian.Uint16(m[6:]))
	i := 12
	for k := 0; k < qd; k++ {
		var ok bool
		if i, ok = skipName(m, i); !ok || i+4 > len(m) {
			return nil, errors.New("повреждённый ответ")
		}
		i += 4
	}
	var ips []string
	for k := 0; k < an; k++ {
		var ok bool
		if i, ok = skipName(m, i); !ok || i+10 > len(m) {
			break
		}
		typ, rl := binary.BigEndian.Uint16(m[i:]), int(binary.BigEndian.Uint16(m[i+8:]))
		i += 10
		if i+rl > len(m) {
			break
		}
		if typ == 1 && rl == 4 {
			ips = append(ips, net.IP(m[i:i+4]).String())
		}
		i += rl
	}
	return ips, nil
}

func resolver(bootstrap string) *net.Resolver {
	if ip := net.ParseIP(strings.TrimSpace(bootstrap)); ip != nil {
		return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", net.JoinHostPort(ip.String(), "53"))
		}}
	}
	return net.DefaultResolver
}

// dialer подключается к хосту; имя узнаёт через bootstrap, чтобы проверка не зависела от системного резолвера.
func dialer(bootstrap string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		h, p, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(h) == nil {
			ips, err := resolver(bootstrap).LookupIP(ctx, "ip4", h)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("не удалось узнать адрес «%s» через bootstrap DNS", h)
			}
			h = ips[0].String()
		}
		return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, net.JoinHostPort(h, p))
	}
}

func frame(c net.Conn, q []byte) ([]byte, error) {
	out := append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, int(binary.BigEndian.Uint16(l[:])))
	_, err := io.ReadFull(c, buf)
	return buf, err
}

// tlsConfig можно подменить в тестах.
var tlsConfig *tls.Config

// Test проверяет сервер addr вида «77.88.8.8», «tls://host», «https://host/path» или «local».
func Test(ctx context.Context, addr, bootstrap string) Result {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return Result{Error: "адрес не задан"}
	}
	start := time.Now()
	done := func(proto string, ips []string, err error) Result {
		r := Result{Proto: proto, Ms: int(time.Since(start).Milliseconds()), IPs: ips}
		if err != nil {
			r.Error = clean(err)
			return r
		}
		r.OK = true
		return r
	}
	if addr == "local" {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", testName)
		var s []string
		for _, ip := range ips {
			s = append(s, ip.String())
		}
		return done("системный резолвер", s, err)
	}
	if !strings.Contains(addr, "://") {
		addr = "udp://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil || u.Hostname() == "" {
		return Result{Error: "не удалось разобрать адрес"}
	}
	q := buildQuery()
	port := u.Port()
	dial := dialer(bootstrap)
	switch u.Scheme {
	case "udp":
		if port == "" {
			port = "53"
		}
		c, err := dial(ctx, "udp", net.JoinHostPort(u.Hostname(), port))
		if err != nil {
			return done("UDP", nil, err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := c.Write(q); err != nil {
			return done("UDP", nil, err)
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			return done("UDP", nil, err)
		}
		ips, err := parse(q, buf[:n])
		return done("UDP", ips, err)
	case "tcp", "tls":
		if port == "" {
			port = map[string]string{"tcp": "53", "tls": "853"}[u.Scheme]
		}
		c, err := dial(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
		if err != nil {
			return done(strings.ToUpper(u.Scheme), nil, err)
		}
		defer c.Close()
		if u.Scheme == "tls" {
			cfg := tlsConfig.Clone()
			if cfg == nil {
				cfg = &tls.Config{}
			}
			cfg.ServerName = u.Hostname()
			tc := tls.Client(c, cfg)
			_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
			if err := tc.HandshakeContext(ctx); err != nil {
				return done("DoT", nil, err)
			}
			c = tc
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		m, err := frame(c, q)
		if err != nil {
			return done(strings.ToUpper(u.Scheme), nil, err)
		}
		ips, err := parse(q, m)
		return done(map[string]string{"tcp": "TCP", "tls": "DoT"}[u.Scheme], ips, err)
	case "https":
		path := u.Path
		if path == "" {
			path = "/dns-query"
		}
		hostport := u.Hostname()
		if port != "" {
			hostport = net.JoinHostPort(u.Hostname(), port)
		}
		tr := &http.Transport{DialContext: dial, TLSClientConfig: tlsConfig.Clone(), TLSHandshakeTimeout: 5 * time.Second}
		defer tr.CloseIdleConnections()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+hostport+path, bytes.NewReader(q))
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			return done("DoH", nil, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return done("DoH", nil, fmt.Errorf("HTTP %d", resp.StatusCode))
		}
		m, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
		if err != nil {
			return done("DoH", nil, err)
		}
		ips, err := parse(q, m)
		return done("DoH", ips, err)
	}
	return Result{Proto: strings.ToUpper(u.Scheme), Error: "из панели проверяются только UDP, TCP, DoT и DoH; этот тип работает только в самом ядре"}
}

// clean переводит типичные сетевые ошибки в понятный вид.
func clean(err error) string {
	s := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(s, "i/o timeout") || strings.Contains(s, "deadline exceeded"):
		return "нет ответа за отведённое время — сервер недоступен или трафик режется"
	case strings.Contains(s, "connection refused"):
		return "соединение отклонено"
	case strings.Contains(s, "connection reset") || strings.Contains(s, "EOF"):
		return "соединение разорвано (возможно, блокировка)"
	case strings.Contains(s, "no route") || strings.Contains(s, "network is unreachable"):
		return "нет маршрута до сервера"
	case strings.Contains(s, "certificate"):
		return "ошибка сертификата сервера: " + s
	}
	return s
}
