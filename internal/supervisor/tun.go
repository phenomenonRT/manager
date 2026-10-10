package supervisor

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// ensureTun проверяет, что устройство /dev/net/tun есть; при необходимости пробует подгрузить
// модуль и создать узел устройства. На части прошивок (например, Keenetic) TUN недоступен.
func ensureTun() error {
	const dev = "/dev/net/tun"
	if _, err := os.Stat(dev); err == nil {
		return nil
	}
	for _, m := range [][]string{{"modprobe", "tun"}, {"insmod", "tun"}} {
		if p, err := exec.LookPath(m[0]); err == nil {
			_ = exec.Command(p, m[1:]...).Run()
		}
	}
	if _, err := os.Stat(dev); err != nil {
		_ = os.MkdirAll("/dev/net", 0o755)
		_ = syscall.Mknod(dev, syscall.S_IFCHR|0o666, int(10<<8|200))
	}
	if _, err := os.Stat(dev); err != nil {
		return errors.New("режим TUN недоступен: в системе нет /dev/net/tun (нет модуля ядра tun). " +
			"Отключите TUN в разделе «Входящие, TUN, сеть» и включите прозрачный прокси в режиме tproxy или redirect — он не требует TUN")
	}
	return nil
}
