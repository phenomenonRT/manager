package importer

import "testing"

const awgBackup = `[{"id":"x","tag":"srv","endpoint":{"address":["10.43.199.7/32"],"content_padding_addition":"11-94","disable_cookies":true,
"h1":"1","h2":"2","h3":"3","h4":"4","header_protection_key":"HPK","i1":"<b 0xcd>","jc":5,"jmax":448,"jmin":113,
"keepalive_timeout":"10-24","max_handshake_attempts":"16","mtu":1320,
"peers":[{"address":"203.0.113.5","allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive_interval":"25-27","port":51305,"preshared_key":"PSK","public_key":"PUB"}],
"private_key":"PRIV","random_trailers":true,"reject_after_time":"187-200","rekey_after_time":"121-154","rekey_timeout":"5",
"s1":135,"s2":107,"s3":15,"s4":14,"type":"awg","useIntegratedTun":false}}]`

func TestParseAWGJSONBackup(t *testing.T) {
	res := Parse(awgBackup)
	if len(res.Errors) != 0 || len(res.Nodes) != 1 {
		t.Fatalf("nodes=%d errors=%v", len(res.Nodes), res.Errors)
	}
	n := res.Nodes[0]
	if n.Type != "awg" || n.Name != "srv" || n.Server != "203.0.113.5" || n.Port != 51305 || n.MTU != 1320 || n.Keepalive != "25-27" || n.PreSharedKey != "PSK" {
		t.Errorf("узел разобран неверно: %+v", n)
	}
	a := n.AWG
	if a == nil || a.Jc != 5 || a.S4 != 14 || a.H4 != "4" || a.HeaderProtectionKey != "HPK" || !a.RandomTrailers || !a.DisableCookies ||
		a.ContentPadding != "11-94" || a.RekeyTimeout != "5" || a.MaxHandshakeAttempts != "16" || a.I1 != "<b 0xcd>" {
		t.Errorf("параметры AWG разобраны неверно: %+v", a)
	}
}

func TestParseAWGConfExtras(t *testing.T) {
	conf := "[Interface]\nPrivateKey = PRIV\nAddress = 10.0.0.2/32\nJc = 5\nHeaderProtectionKey = HPK\nRandomTrailers = true\nRekeyTimeout = 5\n" +
		"[Peer]\nPublicKey = PUB\nEndpoint = 203.0.113.5:51305\nPersistentKeepalive = 25-27\nAllowedIPs = 0.0.0.0/0\n"
	n, err := ParseWireGuardConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != "awg" || n.AWG == nil || n.AWG.HeaderProtectionKey != "HPK" || !n.AWG.RandomTrailers || n.AWG.RekeyTimeout != "5" || n.Keepalive != "25-27" {
		t.Errorf("расширенные ключи .conf не разобраны: %+v %+v", n, n.AWG)
	}
}

func TestParseAWGJSONBroken(t *testing.T) {
	if res := Parse(`[{"type":"awg","tag":"x"}]`); len(res.Errors) == 0 {
		t.Error("ожидалась ошибка о нехватке данных")
	}
}

func TestParseAWGConfFlagsAndAddress(t *testing.T) {
	conf := "[Interface]\nPrivateKey = PRIV\nAddress = 10.0.0.2, fd00::2\nJc = 4\nRandomTrailers = on\nDisableCookies = off\nListenPort = 1234\nDNS = 1.1.1.1\n" +
		"[Peer]\nPublicKey = PUB\nEndpoint = 203.0.113.5:51305\nAllowedIPs = 0.0.0.0/0\n"
	n, err := ParseWireGuardConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Addresses) != 2 || n.Addresses[0] != "10.0.0.2/32" || n.Addresses[1] != "fd00::2/128" {
		t.Errorf("адреса без маски не дополнены: %v", n.Addresses)
	}
	if n.AWG == nil || !n.AWG.RandomTrailers || n.AWG.DisableCookies {
		t.Errorf("флаги on/off разобраны неверно: %+v", n.AWG)
	}
}
