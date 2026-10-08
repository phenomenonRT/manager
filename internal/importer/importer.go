// Package importer разбирает ссылки-подписки (vless://, vmess://, …) и
// конфиги WireGuard в узлы единой модели.
package importer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"corepanel/internal/model"
)

// Result — итог импорта.
type Result struct {
	Nodes  []model.Node `json:"nodes"`
	Errors []string     `json:"errors"`
}

// Parse принимает произвольный текст: список ссылок, base64-подписку или
// конфиг WireGuard (.conf).
func Parse(text string) Result {
	text = strings.TrimSpace(strings.TrimPrefix(text, "\uFEFF"))
	var res Result
	if text == "" {
		res.Errors = append(res.Errors, "пустой ввод")
		return res
	}
	if strings.Contains(text, "[Interface]") && strings.Contains(text, "[Peer]") {
		n, err := ParseWireGuardConf(text)
		if err != nil {
			res.Errors = append(res.Errors, err.Error())
		} else {
			res.Nodes = append(res.Nodes, n)
		}
		return res
	}
	text = DecodeSubscription(text)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n, err := ParseLink(line)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", shorten(line), err))
			continue
		}
		res.Nodes = append(res.Nodes, n)
	}
	if len(res.Nodes) == 0 && len(res.Errors) == 0 {
		res.Errors = append(res.Errors, "не найдено ни одной ссылки")
	}
	return res
}

func shorten(s string) string {
	if len(s) > 48 {
		return s[:45] + "…"
	}
	return s
}

// DecodeSubscription раскодирует тело подписки, если оно целиком в base64.
func DecodeSubscription(body string) string {
	body = strings.TrimSpace(body)
	if strings.Contains(body, "://") {
		return body
	}
	if dec, ok := decodeB64(strings.Join(strings.Fields(body), "")); ok && strings.Contains(dec, "://") {
		return dec
	}
	return body
}

func decodeB64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), true
		}
	}
	return "", false
}

// ParseLink разбирает одну ссылку.
func ParseLink(link string) (model.Node, error) {
	i := strings.Index(link, "://")
	if i < 0 {
		return model.Node{}, fmt.Errorf("не похоже на ссылку")
	}
	switch strings.ToLower(link[:i]) {
	case "vless":
		return parseVLESS(link)
	case "vmess":
		return parseVMess(link)
	case "trojan":
		return parseTrojan(link)
	case "ss":
		return parseSS(link)
	case "hysteria2", "hy2":
		return parseHysteria2(link)
	case "tuic":
		return parseTUIC(link)
	case "socks", "socks5":
		return parseSocks(link)
	case "wireguard", "wg":
		return parseWGLink(link)
	}
	return model.Node{}, fmt.Errorf("протокол «%s» не поддерживается", link[:i])
}

func hostPort(u *url.URL, defPort int) (string, int, error) {
	host := u.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("не указан сервер")
	}
	port := defPort
	if ps := u.Port(); ps != "" {
		p, err := strconv.Atoi(ps)
		if err != nil || p <= 0 || p > 65535 {
			return "", 0, fmt.Errorf("неверный порт «%s»", ps)
		}
		port = p
	}
	if port == 0 {
		return "", 0, fmt.Errorf("не указан порт")
	}
	return host, port, nil
}

func fragName(u *url.URL, host string, port int) string {
	if f := strings.TrimSpace(u.Fragment); f != "" {
		return f
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truthy(s string) bool {
	switch strings.ToLower(s) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func normNetwork(t string) (string, error) {
	switch strings.ToLower(t) {
	case "", "tcp", "raw":
		return "tcp", nil
	case "ws", "websocket":
		return "ws", nil
	case "grpc", "gun":
		return "grpc", nil
	case "h2", "http":
		return "h2", nil
	case "httpupgrade":
		return "httpupgrade", nil
	}
	return "", fmt.Errorf("транспорт «%s» не поддерживается панелью (можно добавить через «Дополнительно»)", t)
}

// applyTransportTLS читает общие параметры транспорта и TLS из query.
func applyTransportTLS(n *model.Node, q url.Values) error {
	net, err := normNetwork(q.Get("type"))
	if err != nil {
		return err
	}
	n.Network = net
	n.Host = q.Get("host")
	n.Path = q.Get("path")
	if net == "grpc" {
		n.ServiceName = q.Get("serviceName")
		if n.ServiceName == "" {
			n.ServiceName = q.Get("service_name")
		}
	}
	switch strings.ToLower(q.Get("security")) {
	case "tls", "xtls":
		n.TLS = true
	case "reality":
		n.TLS = true
		n.Reality = true
	}
	n.SNI = q.Get("sni")
	if n.SNI == "" {
		n.SNI = q.Get("peer")
	}
	n.Fingerprint = q.Get("fp")
	n.ALPN = splitList(q.Get("alpn"))
	n.Insecure = truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure"))
	n.PublicKey = q.Get("pbk")
	n.ShortID = q.Get("sid")
	return nil
}

func parseVLESS(link string) (model.Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return model.Node{}, err
	}
	host, port, err := hostPort(u, 0)
	if err != nil {
		return model.Node{}, err
	}
	n := model.Node{Type: "vless", Server: host, Port: port, UUID: u.User.Username(), UDP: true}
	if n.UUID == "" {
		return n, fmt.Errorf("нет UUID")
	}
	q := u.Query()
	if err := applyTransportTLS(&n, q); err != nil {
		return n, err
	}
	n.Flow = q.Get("flow")
	n.Name = fragName(u, host, port)
	return n, nil
}

func parseVMess(link string) (model.Node, error) {
	raw := strings.TrimPrefix(link, link[:strings.Index(link, "://")+3])
	dec, ok := decodeB64(raw)
	if !ok {
		return model.Node{}, fmt.Errorf("не удалось раскодировать base64")
	}
	var j map[string]any
	if err := json.Unmarshal([]byte(dec), &j); err != nil {
		return model.Node{}, fmt.Errorf("неверный JSON: %v", err)
	}
	str := func(k string) string {
		switch v := j[k].(type) {
		case string:
			return v
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return ""
	}
	port, _ := strconv.Atoi(str("port"))
	aid, _ := strconv.Atoi(str("aid"))
	n := model.Node{Type: "vmess", Server: str("add"), Port: port, UUID: str("id"), AlterID: aid, Method: str("scy"), UDP: true}
	if n.Server == "" || n.Port == 0 || n.UUID == "" {
		return n, fmt.Errorf("не хватает add/port/id")
	}
	if n.Method == "" {
		n.Method = "auto"
	}
	net, err := normNetwork(str("net"))
	if err != nil {
		return n, err
	}
	n.Network = net
	n.Host = str("host")
	n.Path = str("path")
	if net == "grpc" {
		n.ServiceName = n.Path
		n.Path = ""
	}
	if t := str("tls"); t == "tls" {
		n.TLS = true
	}
	n.SNI = str("sni")
	n.Fingerprint = str("fp")
	n.ALPN = splitList(str("alpn"))
	n.Insecure = truthy(str("allowInsecure"))
	n.Name = strings.TrimSpace(str("ps"))
	if n.Name == "" {
		n.Name = fmt.Sprintf("%s:%d", n.Server, n.Port)
	}
	return n, nil
}

func parseTrojan(link string) (model.Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return model.Node{}, err
	}
	host, port, err := hostPort(u, 443)
	if err != nil {
		return model.Node{}, err
	}
	pw := u.User.Username()
	if p, ok := u.User.Password(); ok {
		pw += ":" + p
	}
	n := model.Node{Type: "trojan", Server: host, Port: port, Password: pw, UDP: true, TLS: true}
	if pw == "" {
		return n, fmt.Errorf("нет пароля")
	}
	q := u.Query()
	if err := applyTransportTLS(&n, q); err != nil {
		return n, err
	}
	n.TLS = true
	n.Name = fragName(u, host, port)
	return n, nil
}

func parseSS(link string) (model.Node, error) {
	rest := strings.TrimPrefix(link, "ss://")
	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "/")
	var userinfo, hostport string
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		userinfo, hostport = rest[:i], rest[i+1:]
		if dec, ok := decodeB64(userinfo); ok && strings.Contains(dec, ":") {
			userinfo = dec
		} else if un, err := url.PathUnescape(userinfo); err == nil {
			userinfo = un
		}
	} else {
		dec, ok := decodeB64(rest)
		if !ok {
			return model.Node{}, fmt.Errorf("не удалось раскодировать ссылку")
		}
		i := strings.LastIndex(dec, "@")
		if i < 0 {
			return model.Node{}, fmt.Errorf("неверный формат")
		}
		userinfo, hostport = dec[:i], dec[i+1:]
	}
	ci := strings.Index(userinfo, ":")
	if ci < 0 {
		return model.Node{}, fmt.Errorf("нет метода шифрования или пароля")
	}
	host, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return model.Node{}, fmt.Errorf("неверный адрес сервера")
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return model.Node{}, fmt.Errorf("неверный порт")
	}
	if q, _ := url.ParseQuery(query); q.Get("plugin") != "" {
		return model.Node{}, fmt.Errorf("плагины shadowsocks (%s) не поддерживаются", strings.SplitN(q.Get("plugin"), ";", 2)[0])
	}
	n := model.Node{Type: "shadowsocks", Server: host, Port: port, Method: userinfo[:ci], Password: userinfo[ci+1:], UDP: true, Name: strings.TrimSpace(name)}
	if n.Name == "" {
		n.Name = fmt.Sprintf("%s:%d", host, port)
	}
	return n, nil
}

func parseHysteria2(link string) (model.Node, error) {
	// порты вида 443,5000-6000 ломают url.Parse — берём первый
	norm := link
	u, err := url.Parse(norm)
	if err != nil {
		if at := strings.LastIndex(link, "@"); at >= 0 {
			hp := link[at+1:]
			end := len(hp)
			for i, c := range hp {
				if c == '/' || c == '?' || c == '#' {
					end = i
					break
				}
			}
			h := hp[:end]
			if ci := strings.LastIndex(h, ":"); ci >= 0 {
				first := strings.FieldsFunc(h[ci+1:], func(r rune) bool { return r == ',' || r == '-' })
				if len(first) > 0 {
					norm = link[:at+1] + h[:ci+1] + first[0] + hp[end:]
					u, err = url.Parse(norm)
				}
			}
		}
		if err != nil || u == nil {
			return model.Node{}, fmt.Errorf("неверная ссылка")
		}
	}
	host, port, err := hostPort(u, 443)
	if err != nil {
		return model.Node{}, err
	}
	pw := u.User.Username()
	if p, ok := u.User.Password(); ok {
		pw += ":" + p
	}
	if pw == "" {
		return model.Node{}, fmt.Errorf("нет пароля")
	}
	q := u.Query()
	n := model.Node{Type: "hysteria2", Server: host, Port: port, Password: pw, TLS: true,
		SNI: q.Get("sni"), Insecure: truthy(q.Get("insecure")), ALPN: splitList(q.Get("alpn")),
		Obfs: q.Get("obfs"), ObfsPassword: q.Get("obfs-password")}
	n.Name = fragName(u, host, port)
	return n, nil
}

func parseTUIC(link string) (model.Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return model.Node{}, err
	}
	host, port, err := hostPort(u, 443)
	if err != nil {
		return model.Node{}, err
	}
	pw, _ := u.User.Password()
	q := u.Query()
	n := model.Node{Type: "tuic", Server: host, Port: port, UUID: u.User.Username(), Password: pw, TLS: true,
		SNI: q.Get("sni"), ALPN: splitList(q.Get("alpn")), Insecure: truthy(q.Get("allow_insecure")) || truthy(q.Get("insecure")),
		Congestion: q.Get("congestion_control"), UDPRelayMode: q.Get("udp_relay_mode")}
	if n.UUID == "" {
		return n, fmt.Errorf("нет UUID")
	}
	n.Name = fragName(u, host, port)
	return n, nil
}

func parseSocks(link string) (model.Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return model.Node{}, err
	}
	host, port, err := hostPort(u, 1080)
	if err != nil {
		return model.Node{}, err
	}
	pw, _ := u.User.Password()
	n := model.Node{Type: "socks", Server: host, Port: port, Username: u.User.Username(), Password: pw, UDP: true}
	n.Name = fragName(u, host, port)
	return n, nil
}

func parseWGLink(link string) (model.Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return model.Node{}, err
	}
	host, port, err := hostPort(u, 51820)
	if err != nil {
		return model.Node{}, err
	}
	q := u.Query()
	n := model.Node{Type: "wireguard", Server: host, Port: port, PrivateKey: u.User.Username(),
		PeerPublicKey: firstNonEmpty(q.Get("publickey"), q.Get("public_key")),
		PreSharedKey:  firstNonEmpty(q.Get("presharedkey"), q.Get("psk")),
		Addresses:     splitList(q.Get("address")), UDP: true}
	if v, err := strconv.Atoi(q.Get("mtu")); err == nil {
		n.MTU = v
	}
	for _, p := range splitList(q.Get("reserved")) {
		if v, err := strconv.Atoi(p); err == nil {
			n.Reserved = append(n.Reserved, v)
		}
	}
	n.Name = fragName(u, host, port)
	return n, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// ParseWireGuardConf разбирает стандартный wg-quick конфиг.
func ParseWireGuardConf(text string) (model.Node, error) {
	n := model.Node{Type: "wireguard", UDP: true, Name: "wireguard"}
	section := ""
	peers := 0
	var amnezia bool
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.IndexAny(line, "#;"); i == 0 {
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			if section == "peer" {
				peers++
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch section {
		case "interface":
			switch k {
			case "privatekey":
				n.PrivateKey = v
			case "address":
				n.Addresses = append(n.Addresses, splitList(v)...)
			case "mtu":
				n.MTU, _ = strconv.Atoi(v)
			case "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4":
				amnezia = true
			}
		case "peer":
			if peers > 1 {
				continue // поддерживается один пир
			}
			switch k {
			case "publickey":
				n.PeerPublicKey = v
			case "presharedkey":
				n.PreSharedKey = v
			case "allowedips":
				n.AllowedIPs = splitList(v)
			case "endpoint":
				h, ps, err := net.SplitHostPort(v)
				if err != nil {
					return n, fmt.Errorf("неверный Endpoint «%s»", v)
				}
				n.Server = strings.Trim(h, "[]")
				n.Port, _ = strconv.Atoi(ps)
			}
		}
	}
	if n.PrivateKey == "" || n.PeerPublicKey == "" || n.Server == "" || n.Port == 0 || len(n.Addresses) == 0 {
		return n, fmt.Errorf("в конфиге WireGuard не хватает PrivateKey, Address, PublicKey или Endpoint")
	}
	if amnezia {
		return n, fmt.Errorf("обнаружены параметры AmneziaWG (Jc/Jmin/S1/H1…): панель их не применяет, поэтому туннель не заработал бы. Импортируйте обычный WireGuard-конфиг или задайте узел вручную через «Дополнительно»")
	}
	n.Name = fmt.Sprintf("wg-%s", n.Server)
	return n, nil
}

// UniqueName подбирает свободное имя, добавляя числовой суффикс.
func UniqueName(base string, used map[string]bool) string {
	base = strings.NewReplacer(",", " ", "\"", "'", "\n", " ", "\r", " ").Replace(strings.TrimSpace(base))
	if base == "" {
		base = "node"
	}
	if r := strings.ToLower(base); r == "direct" || r == "block" || r == "reject" || r == "global" || r == "pass" {
		base += "-node"
	}
	name := base
	for i := 2; used[name]; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	used[name] = true
	return name
}
