//go:build linux

package updater

import (
	"os"
	"syscall"
)

// Reexec заменяет процесс панели новым бинарником (тот же pid, те же аргументы).
func Reexec(exe string) error {
	return syscall.Exec(exe, os.Args, os.Environ())
}
