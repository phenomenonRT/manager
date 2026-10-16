package server

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestStaticETagAndGzip(t *testing.T) {
	big := strings.Repeat("const x = 1;\n", 200)
	h := newStatic(fstest.MapFS{
		"index.html": {Data: []byte("<html></html>")},
		"js/app.js":  {Data: []byte(big)},
		"js/tiny.js": {Data: []byte("x")},
	})
	get := func(p string, hdr map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", p, nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := get("/", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "<html>") {
		t.Fatalf("index: %d %q", w.Code, w.Body.String())
	}
	w := get("/js/app.js", map[string]string{"Accept-Encoding": "gzip"})
	if w.Header().Get("Content-Encoding") != "gzip" || w.Body.Len() >= len(big) {
		t.Fatalf("не сжато: %v %d", w.Header(), w.Body.Len())
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(zr); string(b) != big {
		t.Fatal("после распаковки содержимое отличается")
	}
	if w := get("/js/app.js", nil); w.Header().Get("Content-Encoding") != "" || w.Body.String() != big {
		t.Fatal("без Accept-Encoding должен прийти исходный файл")
	}
	tag := w.Header().Get("ETag")
	if tag == "" {
		t.Fatal("нет ETag")
	}
	if w := get("/js/app.js", map[string]string{"If-None-Match": tag}); w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Fatalf("ожидали 304, получили %d", w.Code)
	}
	if w := get("/js/tiny.js", map[string]string{"Accept-Encoding": "gzip"}); w.Header().Get("Content-Encoding") != "" {
		t.Fatal("мелкие файлы не сжимаем")
	}
	if w := get("/nope.js", nil); w.Code != 404 {
		t.Fatalf("404 ожидался, получили %d", w.Code)
	}
	if w := get("/../../etc/passwd", nil); w.Code != 404 {
		t.Fatalf("обход каталога: %d", w.Code)
	}
}
