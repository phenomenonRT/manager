package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
)

// staticFS отдаёт встроенные файлы интерфейса. Файлы лежат в бинарнике без времени изменения,
// поэтому стандартный FileServer не умеет отвечать «не менялось» и каждый раз отправляет всё заново.
// Здесь для каждого файла считается ETag, а текстовые файлы отдаются сжатыми (на роутере это
// заметно: около 200 КБ в десятках запросов вместо нескольких десятков КБ).
type staticFS struct {
	fsys  fs.FS
	mu    sync.Mutex
	cache map[string]*staticFile
}

type staticFile struct {
	raw, gz []byte
	etag    string
	ctype   string
}

func newStatic(fsys fs.FS) *staticFS { return &staticFS{fsys: fsys, cache: map[string]*staticFile{}} }

func (s *staticFS) load(name string) *staticFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.cache[name]; ok {
		return f
	}
	raw, err := fs.ReadFile(s.fsys, name)
	if err != nil {
		s.cache[name] = nil
		return nil
	}
	sum := sha256.Sum256(raw)
	f := &staticFile{raw: raw, etag: `"` + hex.EncodeToString(sum[:8]) + `"`}
	f.ctype = mime.TypeByExtension(path.Ext(name))
	if f.ctype == "" {
		f.ctype = http.DetectContentType(raw)
	}
	if len(raw) > 512 && (strings.HasPrefix(f.ctype, "text/") || strings.Contains(f.ctype, "javascript") ||
		strings.Contains(f.ctype, "json") || strings.Contains(f.ctype, "svg")) {
		var b bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
		_, _ = zw.Write(raw)
		_ = zw.Close()
		if b.Len() < len(raw) {
			f.gz = b.Bytes()
		}
	}
	s.cache[name] = f
	return f
}

func (s *staticFS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	f := s.load(name)
	if f == nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", f.ctype)
	h.Set("ETag", f.etag)
	h.Set("Cache-Control", "no-cache") // всегда спрашиваем, но по ETag получаем 304 без тела
	h.Add("Vary", "Accept-Encoding")
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, f.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body := f.raw
	if f.gz != nil && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		h.Set("Content-Encoding", "gzip")
		body = f.gz
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
