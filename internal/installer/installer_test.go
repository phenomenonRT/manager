package installer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"corepanel/internal/model"
	"corepanel/internal/platform"
)

func TestPickAssetMihomo(t *testing.T) {
	names := []string{
		"mihomo-linux-amd64-v3-v1.19.0.gz", "mihomo-linux-amd64-compatible-v1.19.0.gz", "mihomo-linux-amd64-v1.19.0.gz",
		"mihomo-linux-arm64-v1.19.0.gz", "mihomo-linux-armv7-v1.19.0.gz", "mihomo-linux-armv5-v1.19.0.gz",
		"mihomo-linux-mipsle-softfloat-v1.19.0.gz", "mihomo-linux-mipsle-hardfloat-v1.19.0.gz",
		"mihomo-linux-mips-softfloat-v1.19.0.gz", "mihomo-linux-amd64-v1.19.0.deb",
		"mihomo-windows-amd64-v1.19.0.zip", "mihomo-linux-386-v1.19.0.gz",
	}
	cases := map[string]string{
		"amd64":  "mihomo-linux-amd64-v1.19.0.gz",
		"arm64":  "mihomo-linux-arm64-v1.19.0.gz",
		"armv7":  "mihomo-linux-armv7-v1.19.0.gz",
		"armv6":  "mihomo-linux-armv5-v1.19.0.gz",
		"mipsle": "mihomo-linux-mipsle-softfloat-v1.19.0.gz",
		"mips":   "mihomo-linux-mips-softfloat-v1.19.0.gz",
		"386":    "mihomo-linux-386-v1.19.0.gz",
	}
	for arch, want := range cases {
		got, err := PickAsset("mihomo", arch, names)
		if err != nil || got != want {
			t.Errorf("%s: %q, %v (ожидалось %q)", arch, got, err, want)
		}
	}
}

func TestPickAssetSingbox(t *testing.T) {
	names := []string{
		"sing-box-1.12.0-linux-amd64.tar.gz", "sing-box-1.12.0-linux-amd64v3.tar.gz",
		"sing-box-1.12.0-linux-arm64.tar.gz", "sing-box-1.12.0-linux-armv7.tar.gz",
		"sing-box-1.12.0-windows-amd64.zip", "sing-box_1.12.0_linux_amd64.deb",
		"sing-box-1.12.0-linux-mips64le.tar.gz",
	}
	for arch, want := range map[string]string{
		"amd64": "sing-box-1.12.0-linux-amd64.tar.gz",
		"arm64": "sing-box-1.12.0-linux-arm64.tar.gz",
		"armv7": "sing-box-1.12.0-linux-armv7.tar.gz",
	} {
		got, err := PickAsset("singbox", arch, names)
		if err != nil || got != want {
			t.Errorf("%s: %q, %v", arch, got, err)
		}
	}
	// для mipsle готовой сборки нет — должна быть понятная ошибка
	if _, err := PickAsset("singbox", "mipsle", names); err == nil {
		t.Error("ожидалась ошибка для mipsle")
	}
	if _, err := PickAsset("singbox", "sparc", names); err == nil {
		t.Error("ожидалась ошибка для неизвестной архитектуры")
	}
}

// Регрессия: Start падал с «unlock of unlocked mutex» (затирался мьютекс в Job).
func TestStartDoesNotCrash(t *testing.T) {
	in := New(platform.Info{Arch: "amd64", BinDir: t.TempDir()})
	d := model.Download{Proxy: "http://127.0.0.1:1"} // недоступный прокси — ошибка быстро
	if err := in.Start(model.CoreMihomo, "", d); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		if s := in.Job.Snapshot(); s.Finished {
			if s.Error == "" {
				t.Fatal("ожидалась ошибка загрузки")
			}
			if err := in.Start(model.CoreMihomo, "", d); err != nil { // повторный запуск после завершения
				t.Fatal(err)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("установка не завершилась")
}

func serveArchive(t *testing.T, name string, data []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	}))
}

func gz(t *testing.T, b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// Распаковка идёт из потока, без промежуточного архива на диске.
func TestFetchExtractStream(t *testing.T) {
	payload := bytes.Repeat([]byte("ELF-bin"), 50000)

	// Mihomo: просто gzip
	srv := serveArchive(t, "m.gz", gz(t, payload))
	defer srv.Close()
	in := New(platform.Info{Arch: "amd64"})
	dir := t.TempDir()
	dst := filepath.Join(dir, "mihomo.new")
	if err := in.fetchExtract(context.Background(), srv.Client(), target{URL: srv.URL}, model.CoreMihomo, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); !bytes.Equal(b, payload) {
		t.Fatal("содержимое mihomo не совпало")
	}

	// sing-box: tar.gz, нужный файл внутри подкаталога
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	_ = tw.WriteHeader(&tar.Header{Name: "sing-box-1.0/LICENSE", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("lic"))
	_ = tw.WriteHeader(&tar.Header{Name: "sing-box-1.0/sing-box", Mode: 0o755, Size: int64(len(payload)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(payload)
	_ = tw.Close()
	srv2 := serveArchive(t, "s.tgz", gz(t, tb.Bytes()))
	defer srv2.Close()
	dst2 := filepath.Join(dir, "sing-box.new")
	if err := in.fetchExtract(context.Background(), srv2.Client(), target{URL: srv2.URL}, model.CoreSingbox, dst2); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst2); !bytes.Equal(b, payload) {
		t.Fatal("содержимое sing-box не совпало")
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".dl-*")); len(m) != 0 {
		t.Fatal("архив не должен сохраняться на диск")
	}

	// оборванный поток должен давать ошибку
	full := gz(t, payload)
	srv3 := serveArchive(t, "cut.gz", full[:len(full)/2])
	defer srv3.Close()
	if err := in.fetchExtract(context.Background(), srv3.Client(), target{URL: srv3.URL}, model.CoreMihomo, filepath.Join(dir, "cut")); err == nil {
		t.Fatal("ожидалась ошибка для обрезанного архива")
	}
}
