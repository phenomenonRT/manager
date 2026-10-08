// Package web встраивает статические файлы интерфейса в бинарник.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var content embed.FS

// FS возвращает файловую систему с корнем в каталоге static.
func FS() fs.FS {
	sub, err := fs.Sub(content, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
