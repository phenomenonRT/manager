package server

import (
	"reflect"
	"testing"
)

func TestParseResolvConf(t *testing.T) {
	got := parseResolvConf("# c\nnameserver 192.168.28.1\nnameserver 127.0.0.1\nnameserver fe80::1%br-lan\nnameserver ::1\nnameserver 0.0.0.0\nsearch lan\nnameserver bad\n")
	want := []string{"192.168.28.1", "fe80::1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
