//go:build !linux

package platform

import "runtime"

func machine() string { return runtime.GOARCH }

// FreeBytes на не-Linux системах не определяется (панель рассчитана на роутеры).
func FreeBytes(path string) uint64 { return 0 }
