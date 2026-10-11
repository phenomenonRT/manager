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

func TestHasDefaultRoute(t *testing.T) {
	hdr := "Iface\tDestination\tGateway\tFlags\n"
	if !hasDefaultRoute(hdr + "wan\t00000000\t0101A8C0\t0003\n") {
		t.Error("маршрут по умолчанию должен находиться")
	}
	if hasDefaultRoute(hdr + "br-lan\t0001A8C0\t00000000\t0001\n") {
		t.Error("только локальная сеть: маршрута по умолчанию нет")
	}
	if hasDefaultRoute(hdr + "wan\t00000000\t0101A8C0\t0002\n") {
		t.Error("маршрут без флага UP не считается")
	}
}
