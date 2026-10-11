package supervisor

import "strings"

// hintFor добавляет к ошибке ядра подсказку, если причина известна.
func hintFor(log string) string {
	l := strings.ToLower(log)
	switch {
	case strings.Contains(l, "nfqueue"):
		return "\n\nПодсказка: режим auto_redirect использует nfqueue, а в ядре прошивки нет его модуля. " +
			"Установите kmod-nft-queue (кнопка «Установить» на странице «Входящие, TUN, сеть») либо отключите auto_redirect в разделе TUN — прозрачный прокси при этом можно оставить в режиме redirect или tproxy."
	case strings.Contains(l, "/dev/net/tun"):
		return "\n\nПодсказка: нет драйвера tun. Установите kmod-tun или отключите TUN."
	}
	return ""
}

// networkNotReady — ядро не стартовало только потому, что в системе ещё нет маршрута в интернет.
func networkNotReady(log string) bool {
	l := strings.ToLower(log)
	return strings.Contains(l, "no route to internet") || strings.Contains(l, "network is unreachable")
}
