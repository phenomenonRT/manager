package supervisor

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

const tunDev = "/dev/net/tun"

// tunWorks проверяет, что устройство не только существует, но и открывается:
// без драйвера узел /dev/net/tun даёт «no such device».
func tunWorks() bool {
	f, err := os.OpenFile(tunDev, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// ensureTun проверяет доступность TUN; при необходимости подгружает модуль и создаёт узел устройства.
// На части прошивок (например, Keenetic без компонента с модулем tun) TUN недоступен.
func ensureTun() error {
	if tunWorks() {
		return nil
	}
	for _, m := range [][]string{{"modprobe", "tun"}, {"insmod", "tun"}} {
		if p, err := exec.LookPath(m[0]); err == nil {
			_ = exec.Command(p, m[1:]...).Run()
		}
	}
	created := false
	if _, err := os.Stat(tunDev); err != nil {
		_ = os.MkdirAll("/dev/net", 0o755)
		created = syscall.Mknod(tunDev, syscall.S_IFCHR|0o666, int(10<<8|200)) == nil
	}
	if tunWorks() {
		return nil
	}
	if created {
		_ = os.Remove(tunDev)
	}
	return errors.New("режим TUN недоступен: в ядре прошивки нет драйвера tun (/dev/net/tun: no such device). " +
		"Отключите TUN в разделе «Входящие, TUN, сеть» — прозрачный прокси работает и без него в режиме redirect или tproxy " +
		"(на Keenetic TUN нужен установленный компонент/модуль ядра tun)")
}
