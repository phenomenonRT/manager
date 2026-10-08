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
	s.Core = model.CoreMihomo
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
	if got.Core != model.CoreMihomo || got.Final != "a" || len(got.Nodes) != 1 {
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

func TestPasswordFlow(t *testing.T) {
	dir := t.TempDir()
	st, _ := Open(dir)
	p, pw, err := st.Panel(":8088")
	if err != nil || pw == "" || !p.MustChange {
		t.Fatalf("первый запуск: %+v %q %v", p, pw, err)
	}
	if !st.CheckLogin("admin", pw) {
		t.Fatal("начальный пароль не подходит")
	}
	if st.CheckLogin("admin", "wrong") || st.CheckLogin("root", pw) {
		t.Fatal("чужие данные приняты")
	}
	if _, pw2, _ := st.Panel(":8088"); pw2 != "" {
		t.Error("пароль не должен показываться повторно")
	}
	if err := st.SetPassword("новый-пароль-123"); err != nil {
		t.Fatal(err)
	}
	st2, _ := Open(dir)
	st2.Panel(":8088")
	if !st2.CheckLogin("admin", "новый-пароль-123") || st2.CheckLogin("admin", pw) {
		t.Error("смена пароля не сработала")
	}
	if st2.PanelInfo().MustChange {
		t.Error("флаг must_change должен сняться")
	}
	if err := ResetPassword(dir, "reset-1"); err != nil {
		t.Fatal(err)
	}
	st3, _ := Open(dir)
	st3.Panel(":8088")
	if !st3.CheckLogin("admin", "reset-1") {
		t.Error("ResetPassword не сработал")
	}
}
