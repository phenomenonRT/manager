package supervisor

// Передача работающего ядра новому процессу панели.
//
// При обновлении панель заменяет сама себя (exec). Раньше перед этим ядро останавливалось, и пока новая
// панель заново проходила проверки и запуск, правила TUN/auto_redirect не действовали: трафик шёл мимо
// туннеля. Теперь ядро продолжает работать, а новая панель подхватывает его по файлу состояния.
//
// Чтобы это было возможно, вывод ядра идёт не в канал (он закрывается при exec, и ядро упало бы на
// первой же записи в лог), а в файл; панель читает этот файл (tailer).

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"corepanel/internal/firewall"
	"corepanel/internal/model"
)

// coreState — то, что нужно новой панели, чтобы подхватить уже работающее ядро.
type coreState struct {
	PID     int    `json:"pid"`
	Core    string `json:"core"`
	Bin     string `json:"bin"`
	Log     string `json:"log"`
	Started int64  `json:"started"`
	Version string `json:"version,omitempty"`
	// Скрипты снятия правил сохраняются как есть: новая версия панели может генерировать другие,
	// а снимать нужно именно те, что были применены.
	FwDown  string `json:"fw_down,omitempty"`
	IfwDown string `json:"ifw_down,omitempty"`
	V6Down  string `json:"v6_down,omitempty"`
}

func (s *Supervisor) stateFile() string {
	return filepath.Join(s.Info.DataDir, "runtime", "core.state")
}

// logPath — файл вывода ядра. По умолчанию в tmpfs (на роутере каталог данных лежит на флеш-памяти, а ядро
// пишет лог постоянно); имя зависит от каталога данных, чтобы разные экземпляры не мешали друг другу.
func (s *Supervisor) logPath(core string) string {
	sum := sha1.Sum([]byte(s.Info.DataDir))
	return filepath.Join(os.TempDir(), fmt.Sprintf("corepanel-%x-%s.log", sum[:4], core))
}

// openCoreLog открывает файл вывода ядра заново (обнуляет). Если во временном каталоге писать нельзя,
// использует каталог ядра.
func (s *Supervisor) openCoreLog(core string) (*os.File, string, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC | os.O_APPEND
	path := s.logPath(core)
	f, err := os.OpenFile(path, flags, 0o600)
	if err == nil {
		return f, path, nil
	}
	path = filepath.Join(s.RuntimeDir(core), "core.log")
	f, err2 := os.OpenFile(path, flags, 0o600)
	if err2 != nil {
		return nil, "", err
	}
	return f, path, nil
}

// saveStateLocked записывает файл состояния запущенного ядра (вызывать под s.mu).
func (s *Supervisor) saveStateLocked() error {
	if !s.running() || s.cmd.Process == nil {
		return fmt.Errorf("ядро не запущено")
	}
	st := coreState{PID: s.cmd.Process.Pid, Core: s.core, Bin: s.bin, Log: s.logFile,
		Started: s.startedAt.Unix(), Version: s.version}
	if s.fw != nil {
		st.FwDown = s.fw.Down
	}
	if s.ifw != nil {
		st.IfwDown = s.ifw.Down
	}
	if s.v6 != nil {
		st.V6Down = s.v6.Down
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.stateFile()), 0o700); err != nil {
		return err
	}
	return writeAtomic(s.stateFile(), b, 0o600)
}

func (s *Supervisor) loadState() (coreState, bool) {
	var st coreState
	b, err := os.ReadFile(s.stateFile())
	if err != nil || json.Unmarshal(b, &st) != nil || st.PID <= 1 || st.Bin == "" || st.Log == "" {
		return coreState{}, false
	}
	return st, true
}

func (s *Supervisor) clearState() { _ = os.Remove(s.stateFile()) }

// procMatches проверяет, что под этим pid всё ещё работает именно ядро, а не чужой процесс с тем же номером.
func procMatches(pid int, bin string) bool {
	if pid <= 1 {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(b) == 0 { // у зомби cmdline пуст
		return false
	}
	// у бинарника имя в argv[0]; у скрипта (обёртка вокруг ядра) — в argv[1], а в argv[0] интерпретатор
	args := strings.Split(string(b), "\x00")
	for i := 0; i < len(args) && i < 2; i++ {
		if args[i] != "" && filepath.Base(args[i]) == filepath.Base(bin) {
			return true
		}
	}
	return false
}

func procAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// HandOver готовит замену процесса панели: сохраняет состояние, ядро и правила остаются на месте.
// Возвращает false, если ядро не запущено или состояние сохранить не удалось: тогда вызывающий
// действует по-старому (останавливает ядро и поднимает его после перезапуска).
func (s *Supervisor) HandOver() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running() {
		return false
	}
	if err := s.saveStateLocked(); err != nil {
		s.Logs.Add("[panel] не удалось сохранить состояние ядра для передачи новой панели: " + err.Error())
		return false
	}
	return true
}

// Adopt подхватывает ядро, оставшееся работать от предыдущего процесса панели. Возвращает true, если подхватило.
func (s *Supervisor) Adopt(set *model.Settings) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running() {
		return false
	}
	st, ok := s.loadState()
	if !ok {
		return false
	}
	if !procMatches(st.PID, st.Bin) {
		s.clearState() // ядра уже нет (или pid занят чужим процессом)
		return false
	}
	proc, err := os.FindProcess(st.PID)
	if err != nil {
		return false
	}
	cmd := &exec.Cmd{Path: st.Bin, Process: proc}
	s.cmd, s.done, s.core = cmd, make(chan struct{}), st.Core
	s.startedAt = time.Unix(st.Started, 0)
	s.lastErr, s.fwErr, s.desired, s.waitNet = "", "", true, false
	s.version, s.bin, s.logFile = st.Version, st.Bin, st.Log
	if st.FwDown != "" {
		s.fw = &firewall.Scripts{Down: st.FwDown}
	}
	if st.IfwDown != "" {
		s.ifw = &firewall.Scripts{Down: st.IfwDown}
	}
	if st.V6Down != "" {
		s.v6 = &firewall.Scripts{Down: st.V6Down}
	}
	if set != nil {
		if res, err := Render(set); err == nil {
			s.warnings = res.Warnings
		}
	}
	s.Logs.Add(fmt.Sprintf("[panel] ядро уже работало (pid %d) — панель подхватила его без перезапуска", st.PID))

	tl := newTailer(st.Log, s.Logs, -1)
	go tl.run()
	done := s.done
	if set != nil {
		go s.refreshRuleSets(set, s.RuntimeDir(st.Core), done)
	}
	go func() {
		// подхваченное ядро — потомок этого же процесса (exec не меняет pid), поэтому его можно «пожать»;
		// если это не так (панель запустили заново), просто проверяем, что процесс жив
		for {
			time.Sleep(time.Second)
			var ws syscall.WaitStatus
			wpid, werr := syscall.Wait4(st.PID, &ws, syscall.WNOHANG, nil)
			if werr == nil && wpid == st.PID {
				break
			}
			if werr == syscall.ECHILD && (!procAlive(st.PID) || !procMatches(st.PID, st.Bin)) {
				break
			}
		}
		tl.Stop()
		close(done)
		s.onExit(cmd, nil)
	}()
	return true
}

// ---------- чтение файла вывода ядра ----------

const (
	maxCoreLog  = 1 << 20  // при превышении файл обнуляется (ядро пишет с O_APPEND и продолжит с начала)
	tailBackLog = 64 << 10 // сколько последнего вывода показать при подхвате ядра
)

// tailer построчно переносит новый текст из файла в LogBuffer.
type tailer struct {
	path string
	logs *LogBuffer
	off  int64
	skip bool // отбросить начало первой (возможно обрезанной) строки
	buf  []byte
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// newTailer читает файл с позиции off; off < 0 — с последних tailBackLog байт.
func newTailer(path string, logs *LogBuffer, off int64) *tailer {
	t := &tailer{path: path, logs: logs, stop: make(chan struct{}), done: make(chan struct{})}
	if off < 0 {
		off = 0
		if fi, err := os.Stat(path); err == nil && fi.Size() > tailBackLog {
			off = fi.Size() - tailBackLog
			t.skip = true
		}
	}
	t.off = off
	return t
}

func (t *tailer) run() {
	defer close(t.done)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-t.stop:
			t.poll()
			if len(t.buf) > 0 {
				t.logs.Add(stripANSI(string(t.buf)))
				t.buf = nil
			}
			return
		case <-tick.C:
			t.poll()
		}
	}
}

// Stop дочитывает файл до конца и завершает чтение.
func (t *tailer) Stop() {
	t.once.Do(func() { close(t.stop) })
	<-t.done
}

func (t *tailer) poll() {
	f, err := os.Open(t.path)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	if fi.Size() < t.off { // файл обнулили
		t.off, t.buf = 0, nil
	}
	chunk := make([]byte, 32<<10)
	for t.off < fi.Size() {
		n, err := f.ReadAt(chunk, t.off)
		if n > 0 {
			t.off += int64(n)
			t.feed(chunk[:n])
		}
		if err != nil {
			break
		}
	}
	if t.off >= maxCoreLog {
		if fi2, err := os.Stat(t.path); err == nil && fi2.Size() == t.off {
			if os.Truncate(t.path, 0) == nil {
				t.off = 0
			}
		}
	}
}

func (t *tailer) feed(data []byte) {
	if t.skip {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return
		}
		data, t.skip = data[i+1:], false
	}
	t.buf = append(t.buf, data...)
	for {
		i := bytes.IndexByte(t.buf, '\n')
		if i < 0 {
			break
		}
		t.logs.Add(stripANSI(string(t.buf[:i])))
		t.buf = t.buf[i+1:]
	}
	if len(t.buf) > 1<<20 { // строка без перевода — не копим бесконечно
		t.logs.Add(stripANSI(string(t.buf)))
		t.buf = nil
	}
}
