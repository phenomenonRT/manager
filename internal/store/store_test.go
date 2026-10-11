package store

import (
	"os"
	"path/filepath"
	"testing"

	"corepanel/internal/model"
)

func TestSettingsRoundTripAndBackup(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := st.Get()
	s.Core = model.CoreAmnezia
	s.Nodes = []model.Node{{Name: "a", Type: "socks", Server: "1.1.1.1", Port: 1080}}
	if err := st.Set(s); err != nil {
		t.Fatal(err)
	}
	s.Final = "a"
	if err := st.Set(s); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := st2.Get()
	if got.Core != model.CoreAmnezia || got.Final != "a" || len(got.Nodes) != 1 {
		t.Errorf("не сохранилось: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "settings.json.bak")); err != nil {
		t.Error("нет резервной копии")
	}
	fi, _ := os.Stat(filepath.Join(dir, "settings.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("права settings.json = %v, ожидалось 0600 (там пароли узлов)", fi.Mode().Perm())
	}
}

func TestGetReturnsCopy(t *testing.T) {
	st, _ := Open(t.TempDir())
	a := st.Get()
	a.Final = "mutated"
	if st.Get().Final == "mutated" {
		t.Error("Get должен возвращать копию")
	}
}

func TestAuthSwitch(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	p, err := st.Panel(":8088")
	if err != nil || p.AuthEnabled || p.Epoch == "" {
		t.Fatalf("первый запуск: вход должен быть выключен: %+v %v", p, err)
	}
	if err := st.SetAuth(true); err != nil {
		t.Fatal(err)
	}
	st2, _ := Open(dir)
	p2, _ := st2.Panel(":8088")
	if !p2.AuthEnabled || p2.Epoch == p.Epoch {
		t.Errorf("включение входа не сохранилось или не сменило epoch: %+v", p2)
	}
}
