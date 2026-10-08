//go:build linux

package platform

import "syscall"

func machine() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	var b []byte
	for _, c := range u.Machine[:] {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// FreeBytes возвращает свободное место на разделе, где лежит path.
func FreeBytes(path string) uint64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	return uint64(st.Bavail) * uint64(st.Bsize)
}
