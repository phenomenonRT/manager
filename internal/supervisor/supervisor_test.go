package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"corepanel/internal/installer"
	"corepanel/internal/model"
	"corepanel/internal/platform"
)

func fakeCore(t *testing.T, runBody string) (*Supervisor, *model.Settings) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	script := `#!/bin/sh
case "$1" in
  version) echo "sing-box version 1.12.3"; exit 0;;
  check) exit 0;;
  run) ` + runBody + `;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "amnezia-box"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	info := platform.Info{OS: platform.Linux, DataDir: filepath.Join(dir, "data"), BinDir: bin}
	set := model.Default()
	set.Normalize()
	sup := New(info, installer.New(info), func() *model.Settings { return set })
	t.Cleanup(func() { sup.Stop() })
	return sup, set
}

func TestStartStop(t *testing.T) {
	sup, set := fakeCore(t, `echo "hello from core"; trap 'exit 0' TERM; while true; do sleep 0.1; done`)
	if err := sup.Start(set); err != nil {
		t.Fatal(err)
	}
	st := sup.Status()
	if st.State != "running" || st.PID == 0 || st.Version != "1.12.3" {
		t.Fatalf("статус: %+v", st)
	}
	if err := sup.Start(set); err == nil {
		t.Error("повторный запуск должен быть отклонён")
	}
	time.Sleep(200 * time.Millisecond)
	if !strings.Contains(strings.Join(sup.Logs.Tail(10), "\n"), "hello from core") {
		t.Errorf("лог ядра не попал в буфер: %v", sup.Logs.Tail(10))
	}
	if _, err := os.Stat(filepath.Join(sup.RuntimeDir("amnezia"), "config.json")); err != nil {
		t.Error("конфиг не записан:", err)
	}
	if err := sup.Stop(); err != nil {
		t.Fatal(err)
	}
	if st := sup.Status(); st.State != "stopped" {
		t.Errorf("после Stop: %+v", st)
	}
}

func TestImmediateCrashReported(t *testing.T) {
	sup, set := fakeCore(t, `echo "FATAL bad option" >&2; exit 3`)
	err := sup.Start(set)
	if err == nil || !strings.Contains(err.Error(), "FATAL bad option") {
		t.Fatalf("ожидалась ошибка с текстом из лога ядра, получено: %v", err)
	}
	if st := sup.Status(); st.State != "failed" {
		t.Errorf("статус после падения: %+v", st)
	}
}

func TestConfigRejectedByCore(t *testing.T) {
	sup, set := fakeCore(t, `sleep 5`)
	// подменяем check на отказ
	p := filepath.Join(sup.Info.BinDir, "amnezia-box")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), "check) exit 0;;", `check) echo "bad outbound" ; exit 1;;`, 1)), 0o755)
	err := sup.Start(set)
	if err == nil || !strings.Contains(err.Error(), "bad outbound") {
		t.Fatalf("ожидался отказ с причиной: %v", err)
	}
}

func TestNotInstalled(t *testing.T) {
	sup, set := fakeCore(t, `sleep 1`)
	os.Remove(filepath.Join(sup.Info.BinDir, "amnezia-box"))
	set.Download.Mirror = ""
	if err := sup.Start(set); err == nil || !strings.Contains(err.Error(), "не установлено") {
		// допускаем, что в PATH окажется настоящий sing-box
		if _, e := os.Stat("/usr/bin/sing-box"); e != nil {
			t.Fatalf("ожидалось «не установлено», получено %v", err)
		}
	}
}

func TestInvalidSettingsBlocked(t *testing.T) {
	sup, set := fakeCore(t, `sleep 1`)
	set.Final = "нет-такого"
	if err := sup.Start(set); err == nil || !strings.Contains(err.Error(), "ошибки") {
		t.Fatalf("невалидные настройки должны блокировать запуск: %v", err)
	}
}
