package dnstest

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func reply(q []byte, rcode byte) []byte {
	r := append([]byte(nil), q...)
	r[2], r[3] = 0x81, 0x80|rcode
	if rcode == 0 {
		r[7] = 1
		r = append(r, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34)
	}
	return r
}

func TestUDPAndTCP(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(reply(buf[:n], 0), a)
		}
	}()
	r := Test(context.Background(), "udp://"+pc.LocalAddr().String(), "")
	if !r.OK || len(r.IPs) != 1 || r.IPs[0] != "93.184.216.34" {
		t.Fatalf("%+v", r)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var l [2]byte
		io.ReadFull(c, l[:])
		q := make([]byte, binary.BigEndian.Uint16(l[:]))
		io.ReadFull(c, q)
		a := reply(q, 5)
		c.Write(append([]byte{byte(len(a) >> 8), byte(len(a))}, a...))
	}()
	r = Test(context.Background(), "tcp://"+ln.Addr().String(), "")
	if r.OK || r.Error != "сервер ответил: отказ (REFUSED)" {
		t.Fatalf("%+v", r)
	}
}

func TestDoH(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, _ := io.ReadAll(req.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(reply(q, 0))
	}))
	defer ts.Close()
	tlsConfig = &tls.Config{InsecureSkipVerify: true}
	defer func() { tlsConfig = nil }()
	r := Test(context.Background(), "https://"+ts.Listener.Addr().String()+"/dns-query", "")
	if !r.OK || r.Proto != "DoH" {
		t.Fatalf("%+v", r)
	}
}

func TestUnsupportedAndEmpty(t *testing.T) {
	if r := Test(context.Background(), "quic://dns.example", ""); r.OK || r.Error == "" {
		t.Fatalf("%+v", r)
	}
	if r := Test(context.Background(), "", ""); r.OK {
		t.Fatal("пустой адрес")
	}
}
