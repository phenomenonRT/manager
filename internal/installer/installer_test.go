package installer

import (
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
