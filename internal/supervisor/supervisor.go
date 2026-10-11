// Package supervisor запускает ядро (sing-box или Mihomo) и следит за ним.
package supervisor

import (
	"bufio"
	"context"
	"corepanel/internal/kmods"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"corepanel/internal/firewall"
	"corepanel/internal/gen"
	"corepanel/internal/installer"
	"corepanel/internal/model"
	"corepanel/internal/platform"
)

// LogBuffer — кольцевой буфер строк лога с подпиской.
type LogBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
	subs  map[chan string]struct{}
}

func NewLogBuffer(max int) *LogBuffer {
	return &LogBuffer{max: max, subs: map[chan string]struct{}{}}
}

func (l *LogBuffer) Add(line string) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}
	l.mu.Lock()
	l.lines = append(l.lines, line)
	if len(l.lines) > l.max {
		l.lines = l.lines[len(l.lines)-l.max:]
	}
	for ch := range l.subs {
		select {
		case ch <- line:
		default: // медленный подписчик не должен тормозить ядро
		}
	}
	l.mu.Unlock()
}

func (l *LogBuffer) Tail(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.lines) {
		n = len(l.lines)
	}
	return append([]string(nil), l.lines[len(l.lines)-n:]...)
}

func (l *LogBuffer) Subscribe() (<-chan string, func()) {
	ch := make(chan string, 256)
	l.mu.Lock()
	l.subs[ch] = struct{}{}
	l.mu.Unlock()
	return ch, func() {
		l.mu.Lock()
		delete(l.subs, ch)
		l.mu.Unlock()
	}
}

// Status — состояние сервиса.
type Status struct {
	State         string   `json:"state"` // stopped | running | failed
	Core          string   `json:"core"`
	PID           int      `json:"pid"`
	UptimeSec     int64    `json:"uptime_sec"`
	Error         string   `json:"error,omitempty"`
	FirewallError string   `json:"firewall_error,omitempty"`
	Restarts      int      `json:"restarts"`
	Version       string   `json:"version,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
	Notice        string   `json:"notice,omitempty"` // не ошибка: например, ожидание сети
}

// Supervisor управляет процессом ядра.
type Supervisor struct {
	Info platform.Info
	Inst *installer.Installer
	Logs *LogBuffer

	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	core      string
	startedAt time.Time
	lastErr   string
	fwErr     string
	fw        *firewall.Scripts
	desired   bool
	restarts  int
	waitNet   bool // ядро не стартовало из-за отсутствия сети: повторяем запуск без красной ошибки
	netLoop   bool
	warnings  []string
	version   string
	getSet    func() *model.Settings
}

// New создаёт супервизор. getSettings вызывается при автоперезапуске.
func New(info platform.Info, inst *installer.Installer, getSettings func() *model.Settings) *Supervisor {
	return &Supervisor{Info: info, Inst: inst, Logs: NewLogBuffer(2000), getSet: getSettings}
}

// RuntimeDir — рабочий каталог ядра.
func (s *Supervisor) RuntimeDir(core string) string {
	return filepath.Join(s.Info.DataDir, "runtime", core)
}

// Render генерирует конфиг для выбранного ядра.
func Render(set *model.Settings) (*gen.Result, error) {
	if issues := set.Validate(); hasError(issues) {
		var msgs []string
		for _, i := range issues {
			if i.Level == "error" {
				msgs = append(msgs, i.Message)
			}
		}
		return nil, fmt.Errorf("в настройках есть ошибки: %s", strings.Join(msgs, "; "))
	}
	if set.Core == model.CoreMihomo {
		return gen.Mihomo(set)
	}
	note := ""
	if set.Tun.Enabled && set.Tun.AutoRedirect && !queueAvailable() {
		cp := *set
		cp.Tun.AutoRedirect = false
		set = &cp
		note = "auto_redirect отключён автоматически: в ядре нет модуля nfqueue (установите kmod-nft-queue, чтобы использовать его)"
	}
	res, err := gen.Singbox(set)
	if err == nil && note != "" {
		res.Warnings = append(res.Warnings, note)
	}
	return res, err
}

var queueAvailable = kmods.QueueAvailable

func hasError(is []model.Issue) bool {
	for _, i := range is {
		if i.Level == "error" {
			return true
		}
	}
	return false
}

// Start генерирует конфиг, проверяет его и запускает ядро.
func (s *Supervisor) Start(set *model.Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startLocked(set, true)
}

func (s *Supervisor) running() bool {
	if s.cmd == nil {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (s *Supervisor) startLocked(set *model.Settings, userInitiated bool) error {
	if s.running() {
		return errors.New("ядро уже запущено")
	}
	bin := s.Inst.Locate(set.Core, set.Download)
	if bin == "" {
		return fmt.Errorf("ядро %s не установлено — установите его в разделе «Компоненты»", installer.BinName(set.Core))
	}
	if set.Tun.Enabled {
		if err := ensureTun(); err != nil {
			s.lastErr = err.Error()
			s.Logs.Add("[panel] " + s.lastErr)
			return err
		}
	}
	res, err := Render(set)
	if err != nil {
		s.lastErr = err.Error()
		return err
	}
	dir := s.RuntimeDir(set.Core)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	cfgPath := filepath.Join(dir, res.Filename)
	if err := writeAtomic(cfgPath, []byte(res.Config), 0o600); err != nil {
		return err
	}

	if out, err := checkConfig(set.Core, bin, dir, cfgPath); err != nil {
		s.lastErr = "ядро отклонило конфигурацию: " + out
		s.Logs.Add("[panel] проверка конфигурации не пройдена: " + out)
		return errors.New(s.lastErr)
	}

	var cmd *exec.Cmd
	if set.Core == model.CoreMihomo {
		cmd = exec.Command(bin, "-d", dir, "-f", cfgPath)
	} else {
		cmd = exec.Command(bin, "run", "-c", cfgPath, "-D", dir)
	}
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		s.lastErr = err.Error()
		return fmt.Errorf("не удалось запустить %s: %v", bin, err)
	}
	s.cmd, s.done, s.core = cmd, make(chan struct{}), set.Core
	s.startedAt, s.lastErr, s.fwErr, s.desired = time.Now(), "", "", true
	s.warnings = res.Warnings
	s.version, _ = installer.Version(context.Background(), set.Core, bin)
	if userInitiated {
		s.restarts = 0
	}
	s.waitNet = false
	s.Logs.Add(fmt.Sprintf("[panel] запущен %s (pid %d), конфиг %s", filepath.Base(bin), cmd.Process.Pid, cfgPath))

	var wg sync.WaitGroup
	pump := func(r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			s.Logs.Add(stripANSI(sc.Text()))
		}
	}
	wg.Add(2)
	go pump(stdout)
	go pump(stderr)
	done := s.done
	go func() {
		wg.Wait()
		err := cmd.Wait()
		close(done) // раньше onExit: Start держит блокировку, пока ждёт done
		s.onExit(cmd, err)
	}()

	// ядро должно пережить первые секунды, иначе считаем запуск неудачным
	select {
	case <-done:
		tail := strings.Join(s.Logs.Tail(6), "\n")
		if networkNotReady(tail) {
			// интернета (маршрута по умолчанию) пока нет, например сразу после загрузки роутера
			s.desired, s.lastErr, s.waitNet = false, "", true
			s.Logs.Add("[panel] нет маршрута в интернет — это не сбой: запуск будет повторяться каждые 10 с, пока не появится сеть")
			if !s.netLoop {
				s.netLoop = true
				go s.waitNetwork()
			}
			return nil
		}
		s.waitNet = false
		s.lastErr = "ядро завершилось сразу после запуска:\n" + tail + hintFor(tail)
		s.desired = false
		return errors.New(s.lastErr)
	case <-time.After(1500 * time.Millisecond):
	}

	if sp, err := firewall.FromSettings(set, s.Info.FirewallBE); err != nil {
		s.fwErr = err.Error()
		s.Logs.Add("[panel] брандмауэр: " + err.Error())
	} else if sp != nil {
		sc, err := firewall.Generate(sp)
		if err == nil {
			err = firewall.Apply(context.Background(), sc)
		}
		if err != nil {
			s.fwErr = err.Error()
			s.Logs.Add("[panel] брандмауэр: " + err.Error())
		} else {
			s.fw = sc
			s.Logs.Add("[panel] правила прозрачного проксирования применены (" + sp.Mode + ", " + sp.Backend + ")")
		}
	}
	return nil
}

func (s *Supervisor) onExit(cmd *exec.Cmd, err error) {
	s.mu.Lock()
	if s.cmd != cmd {
		s.mu.Unlock()
		return
	}
	uptime := time.Since(s.startedAt)
	desired := s.desired
	msg := "ядро остановлено"
	if err != nil {
		msg = fmt.Sprintf("ядро завершилось: %v", err)
	}
	s.Logs.Add("[panel] " + msg)
	if s.fw != nil {
		firewall.Remove(context.Background(), s.fw)
		s.fw = nil
	}
	if desired {
		s.lastErr = msg
	}
	restarts := s.restarts
	s.mu.Unlock()

	if !desired || s.getSet == nil {
		return
	}
	// автоперезапуск с нарастающей паузой; быстрые падения не гоняем бесконечно
	if uptime > 30*time.Second {
		restarts = 0
	}
	if restarts >= 5 {
		s.mu.Lock()
		s.desired = false
		s.lastErr = "ядро падает слишком часто, автоперезапуск отключён: " + msg
		s.Logs.Add("[panel] " + s.lastErr)
		s.mu.Unlock()
		return
	}
	delay := time.Duration(1<<uint(restarts)) * 2 * time.Second
	s.Logs.Add(fmt.Sprintf("[panel] автоперезапуск через %s (попытка %d/5)", delay, restarts+1))
	time.Sleep(delay)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.desired || s.running() {
		return
	}
	s.restarts = restarts + 1
	if err := s.startLocked(s.getSet(), false); err != nil {
		s.Logs.Add("[panel] автоперезапуск не удался: " + err.Error())
	}
}

// waitNetwork повторяет запуск, пока не появится сеть (до 10 минут).
func (s *Supervisor) waitNetwork() {
	defer func() {
		s.mu.Lock()
		s.netLoop = false
		s.mu.Unlock()
	}()
	for i := 0; i < 60; i++ {
		time.Sleep(10 * time.Second)
		s.mu.Lock()
		if !s.waitNet || s.running() || s.getSet == nil {
			s.mu.Unlock()
			return
		}
		err := s.startLocked(s.getSet(), false)
		waiting := s.waitNet
		s.mu.Unlock()
		if err != nil {
			s.Logs.Add("[panel] повторный запуск не удался: " + err.Error())
			return
		}
		if !waiting {
			return
		}
	}
	s.mu.Lock()
	s.waitNet = false
	s.lastErr = "сеть не появилась за 10 минут: проверьте подключение к интернету и запустите ядро вручную"
	s.mu.Unlock()
}

// Stop останавливает ядро и снимает правила брандмауэра.
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	s.desired, s.waitNet = false, false
	cmd, done, fw := s.cmd, s.done, s.fw
	s.fw = nil
	s.mu.Unlock()

	if fw != nil {
		firewall.Remove(context.Background(), fw)
	}
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	default:
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			return errors.New("процесс ядра не завершился")
		}
	}
	return nil
}

// Restart перезапускает ядро с новыми настройками.
func (s *Supervisor) Restart(set *model.Settings) error {
	if err := s.Stop(); err != nil {
		return err
	}
	return s.Start(set)
}

// Status возвращает текущее состояние.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{State: "stopped", Core: s.core, Error: s.lastErr, FirewallError: s.fwErr,
		Restarts: s.restarts, Version: s.version, Warnings: s.warnings}
	if s.running() {
		st.State = "running"
		st.PID = s.cmd.Process.Pid
		st.UptimeSec = int64(time.Since(s.startedAt).Seconds())
	} else if s.waitNet {
		st.State = "waiting"
		st.Notice = "Ждём подключения к интернету (нет маршрута по умолчанию). Ядро запустится само, как только сеть появится."
	} else if s.lastErr != "" {
		st.State = "failed"
	}
	return st
}

// ---------- вспомогательное ----------

func checkConfig(core, bin, dir, cfg string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if core == model.CoreMihomo {
		cmd = exec.CommandContext(ctx, bin, "-t", "-d", dir, "-f", cfg)
	} else {
		cmd = exec.CommandContext(ctx, bin, "check", "-c", cfg, "-D", dir)
	}
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(stripANSI(string(out))), err
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
