package supervisor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const tickCore = `trap 'exit 0' TERM; i=0; while true; do echo "tick $i"; i=$((i+1)); sleep 0.1; done`

func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("не дождались: %s", what)
}

func logHas(s *Supervisor, sub string) bool {
	return strings.Contains(strings.Join(s.Logs.Tail(0), "\n"), sub)
}

// Новая панель подхватывает ядро без перезапуска: тот же pid, лог продолжает идти, Stop останавливает именно его.
func TestAdoptRunningCore(t *testing.T) {
	dir := t.TempDir()
	old, set := fakeCoreIn(t, dir, tickCore)
	if err := old.Start(set); err != nil {
		t.Fatal(err)
	}
	pid := old.Status().PID
	if !old.HandOver() {
		t.Fatal("HandOver вернул false при работающем ядре")
	}

	fresh, _ := fakeCoreIn(t, dir, tickCore) // тот же каталог данных, как после exec
	if !fresh.Adopt(set) {
		t.Fatal("ядро не подхвачено")
	}
	st := fresh.Status()
	if st.State != "running" || st.PID != pid {
		t.Fatalf("после подхвата: %+v, ждали pid %d", st, pid)
	}
	waitFor(t, "строки ядра в логе новой панели", 3*time.Second, func() bool { return logHas(fresh, "tick ") })

	if err := fresh.Stop(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "завершение процесса ядра", 5*time.Second, func() bool {
		return !procMatches(pid, "amnezia-box") && syscall.Kill(pid, 0) != nil || isZombie(pid)
	})
	if _, err := os.Stat(fresh.stateFile()); err == nil {
		t.Error("файл состояния должен быть удалён после Stop")
	}
}

func isZombie(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	i := strings.LastIndexByte(string(b), ')')
	return i > 0 && i+2 < len(b) && b[i+2] == 'Z'
}

func TestAdoptIgnoresStaleState(t *testing.T) {
	dir := t.TempDir()
	sup, set := fakeCoreIn(t, dir, tickCore)
	os.MkdirAll(filepath.Dir(sup.stateFile()), 0o700)
	// pid 1 и несуществующие pid не должны считаться ядром
	os.WriteFile(sup.stateFile(), []byte(`{"pid":1,"bin":"/x/amnezia-box","log":"/tmp/none"}`), 0o600)
	if sup.Adopt(set) {
		t.Fatal("подхват по pid 1")
	}
	os.WriteFile(sup.stateFile(), []byte(`{"pid":999999,"bin":"/x/amnezia-box","log":"/tmp/none"}`), 0o600)
	if sup.Adopt(set) {
		t.Fatal("подхват несуществующего процесса")
	}
	if _, err := os.Stat(sup.stateFile()); err == nil {
		t.Error("устаревший файл состояния должен быть удалён")
	}
	os.WriteFile(sup.stateFile(), []byte(`мусор`), 0o600)
	if sup.Adopt(set) {
		t.Fatal("подхват по битому файлу")
	}
}

func TestHandOverWithoutCore(t *testing.T) {
	sup, _ := fakeCore(t, `sleep 5`)
	if sup.HandOver() {
		t.Error("HandOver без запущенного ядра должен вернуть false")
	}
}

// Сквозная проверка главного: ядро переживает настоящий exec процесса панели и продолжает писать лог.
// Тест запускает сам себя дважды (до и после exec), как это делает панель при обновлении.
func TestCoreSurvivesPanelExec(t *testing.T) {
	if os.Getenv("CP_STAGE") != "" {
		t.Skip("вспомогательный запуск")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperPanelExec$", "-test.v")
	cmd.Env = append(os.Environ(), "CP_STAGE=1", "CP_DIR="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "EXEC-SURVIVED") {
		t.Fatalf("ядро не пережило exec панели: %v\n%s", err, out)
	}
	pidb, _ := os.ReadFile(filepath.Join(dir, "core.pid"))
	pid, _ := strconv.Atoi(strings.TrimSpace(string(pidb)))
	if pid > 1 && syscall.Kill(pid, 0) == nil && !isZombie(pid) {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Errorf("ядро (pid %d) осталось жить после Stop новой панели", pid)
	}
}

func TestHelperPanelExec(t *testing.T) {
	stage, dir := os.Getenv("CP_STAGE"), os.Getenv("CP_DIR")
	if stage == "" {
		t.Skip("вспомогательный процесс")
	}
	sup, set := fakeCoreIn(t, dir, tickCore)
	pidFile := filepath.Join(dir, "core.pid")
	switch stage {
	case "1":
		if err := sup.Start(set); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(pidFile, []byte(strconv.Itoa(sup.Status().PID)), 0o600)
		time.Sleep(300 * time.Millisecond)
		if !sup.HandOver() {
			t.Fatal("HandOver")
		}
		var env []string
		for _, e := range os.Environ() {
			if !strings.HasPrefix(e, "CP_STAGE=") {
				env = append(env, e)
			}
		}
		env = append(env, "CP_STAGE=2")
		if err := syscall.Exec(os.Args[0], []string{os.Args[0], "-test.run=^TestHelperPanelExec$", "-test.v"}, env); err != nil {
			t.Fatal(err)
		}
	case "2":
		pidb, _ := os.ReadFile(pidFile)
		pid, _ := strconv.Atoi(strings.TrimSpace(string(pidb)))
		if !sup.Adopt(set) {
			t.Fatal("ядро не подхвачено после exec")
		}
		if st := sup.Status(); st.State != "running" || st.PID != pid {
			t.Fatalf("после exec: %+v, ждали pid %d", st, pid)
		}
		// ядро писало в лог до exec; убеждаемся, что оно пишет и после него (иначе упало бы на закрытом канале)
		before := countTicks(sup)
		time.Sleep(700 * time.Millisecond)
		if after := countTicks(sup); after <= before || syscall.Kill(pid, 0) != nil {
			t.Fatalf("ядро не пишет в лог после exec: было %d, стало %d", before, after)
		}
		if err := sup.Stop(); err != nil {
			t.Fatal(err)
		}
		t.Log("EXEC-SURVIVED")
	}
}

func countTicks(s *Supervisor) int {
	return strings.Count(strings.Join(s.Logs.Tail(0), "\n"), "tick ")
}
