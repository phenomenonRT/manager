//go:build !linux

package updater

import "errors"

func Reexec(exe string) error {
	return errors.New("перезапуск доступен только на Linux")
}
