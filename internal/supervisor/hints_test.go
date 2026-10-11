package supervisor

import "testing"

func TestNetworkNotReady(t *testing.T) {
	if !networkNotReady("FATAL start endpoint/awg[x]: create ipv4 connection: listen udp :0: no route to internet") {
		t.Error("должно распознаваться")
	}
	if networkNotReady("FATAL decode config: unknown field") {
		t.Error("ложное срабатывание")
	}
}
