// Package podkop — управление Podkop (https://github.com/itdoginfo/podkop) на OpenWrt:
// обнаружение, установка по официальной инструкции, управление службой и удаление.
//
// Podkop сам управляет sing-box, dnsmasq и правилами nft, поэтому одновременно с
// панелью его запускать нельзя: оба перехватывают DNS и трафик.
package podkop

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"corepanel/internal/platform"
)

const (
	initScript = "/etc/init.d/podkop"

	// Рекомендации из документации Podkop (МБ свободного места).
	minFreeMB          = 20
	minFreeNoSingboxMB = 40
)

// latestURL — последний релиз Podkop (переопределяется в тестах).
var latestURL = "https://api.github.com/repos/itdoginfo/podkop/releases/latest"

// Manager выполняет операции с Podkop; одновременно идёт не более одной.
type Manager struct {
	Info platform.Info

	mu      sync.Mutex
	running bool
	title   string
	lines   []string
	err     string
	done    bool
}

func New(info platform.Info) *Manager { return &Manager{Info: info} }

// Job — состояние текущей или последней операции.
type Job struct {
	Title    string   `json:"title"`
	Running  bool     `json:"running"`
	Finished bool     `json:"finished"`
	Error    string   `json:"error,omitempty"`
	Output   []string `json:"output"`
}

// Status — сведения о Podkop.
type Status struct {
	Supported  bool   `json:"supported"`
	Reason     string `json:"reason,omitempty"`
	Installed  bool   `json:"installed"`
	Version    string `json:"version,omitempty"`
	Running    bool   `json:"running"`
	PkgManager string `json:"pkg_manager,omitempty"`
	FreeMB     int    `json:"free_mb"`
	NeedMB     int    `json:"need_mb"`
	Job        Job    `json:"job"`
}

func (m *Manager) supported() (bool, string) {
	if m.Info.OS != platform.OpenWrt {
		return false, "Podkop работает только на OpenWrt (24.10 и новее). На Keenetic используйте sing-box или Mihomo через эту панель."
	}
	return true, ""
}

func pkgManager() string {
	if _, err := exec.LookPath("opkg"); err == nil {
		return "opkg"
	}
	if _, err := exec.LookPath("apk"); err == nil {
		return "apk"
	}
	return ""
}

// needMB — сколько места нужно для установки: больше, если sing-box ещё не стоит.
func needMB() int {
	if _, err := exec.LookPath("sing-box"); err != nil {
		return minFreeNoSingboxMB
	}
	return minFreeMB
}

func freeMB() int {
	dir := "/"
	if st, err := os.Stat("/overlay"); err == nil && st.IsDir() {
		dir = "/overlay"
	}
	return int(platform.FreeBytes(dir) / (1 << 20))
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Installed — Podkop установлен (есть его init-скрипт).
func Installed() bool {
	_, err := os.Stat(initScript)
	return err == nil
}

// IsRunning — служба Podkop запущена. Используется и для защиты от конфликта при запуске ядра панели.
func IsRunning(ctx context.Context) bool {
	if !Installed() {
		return false
	}
	out, err := run(ctx, initScript, "status")
	if err != nil {
		return false
	}
	l := strings.ToLower(out)
	for _, bad := range []string{"inactive", "not running", "stopped", "dead"} {
		if strings.Contains(l, bad) {
			return false
		}
	}
	return true
}

func version(ctx context.Context, pm string) string {
	switch pm {
	case "opkg":
		if out, err := run(ctx, "opkg", "list-installed", "podkop"); err == nil {
			if _, v, ok := strings.Cut(out, " - "); ok {
				return strings.TrimSpace(strings.SplitN(v, "\n", 2)[0])
			}
		}
	case "apk":
		if out, err := run(ctx, "apk", "info", "-v", "podkop"); err == nil {
			return strings.TrimPrefix(strings.SplitN(out, "\n", 2)[0], "podkop-")
		}
	}
	return ""
}

// Status собирает текущее состояние.
func (m *Manager) Status(ctx context.Context) Status {
	st := Status{FreeMB: freeMB(), NeedMB: needMB()}
	st.Supported, st.Reason = m.supported()
	m.mu.Lock()
	st.Job = Job{Title: m.title, Running: m.running, Finished: m.done, Error: m.err, Output: append([]string{}, m.lines...)}
	m.mu.Unlock()
	if !st.Supported {
		return st
	}
	st.PkgManager = pkgManager()
	st.Installed = Installed()
	if st.Installed {
		st.Version = version(ctx, st.PkgManager)
		st.Running = IsRunning(ctx)
	}
	return st
}

// Control управляет службой: start, stop, restart, enable, disable.
func (m *Manager) Control(ctx context.Context, action string) (string, error) {
	if ok, why := m.supported(); !ok {
		return "", errors.New(why)
	}
	if !Installed() {
		return "", errors.New("Podkop не установлен")
	}
	switch action {
	case "start", "stop", "restart", "enable", "disable":
	default:
		return "", fmt.Errorf("неизвестное действие «%s»", action)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, initScript, action).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("podkop %s: %v: %s", action, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func (m *Manager) begin(title string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return errors.New("операция уже выполняется")
	}
	m.running, m.done, m.err, m.title, m.lines = true, false, "", title, nil
	return nil
}

func (m *Manager) add(line string) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}
	m.mu.Lock()
	m.lines = append(m.lines, line)
	if len(m.lines) > 300 {
		m.lines = m.lines[len(m.lines)-300:]
	}
	m.mu.Unlock()
}

func (m *Manager) finish(err error) {
	m.mu.Lock()
	m.running, m.done = false, true
	if err != nil {
		m.err = err.Error()
	}
	m.mu.Unlock()
}

// Install запускает официальный установщик (при mirror=true — через зеркало podkop.net,
// если GitHub недоступен). Ввод закрыт: установщик не должен ждать ответов.
func (m *Manager) Install() error {
	if ok, why := m.supported(); !ok {
		return errors.New(why)
	}
	if pkgManager() == "" {
		return errors.New("в системе нет opkg или apk")
	}
	need := needMB()
	if f := freeMB(); f > 0 && f < need {
		return fmt.Errorf("свободно %d МБ, для установки Podkop нужно не меньше %d МБ (sing-box ставится как зависимость). Освободите место или используйте extroot", f, need)
	}
	return m.installLatest()
}

// Remove останавливает и удаляет Podkop.
func (m *Manager) Remove() error {
	if ok, why := m.supported(); !ok {
		return errors.New(why)
	}
	pm := pkgManager()
	if pm == "" {
		return errors.New("в системе нет opkg или apk")
	}
	rm := "opkg remove luci-i18n-podkop-ru luci-app-podkop podkop"
	if pm == "apk" {
		rm = "apk del luci-i18n-podkop-ru luci-app-podkop podkop"
	}
	return m.exec("Удаление Podkop", "[ -x "+initScript+" ] && "+initScript+" stop; "+rm, 5*time.Minute)
}

func (m *Manager) exec(title, shell string, limit time.Duration) error {
	if err := m.begin(title); err != nil {
		return err
	}
	m.add("$ " + shell)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), limit)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sh", "-c", shell)
		cmd.Stdin = nil
		pr, pw := io.Pipe()
		cmd.Stdout, cmd.Stderr = pw, pw
		if err := cmd.Start(); err != nil {
			m.finish(err)
			return
		}
		go func() {
			sc := bufio.NewScanner(pr)
			sc.Buffer(make([]byte, 64*1024), 256*1024)
			for sc.Scan() {
				m.add(sc.Text())
			}
		}()
		err := cmd.Wait()
		_ = pw.Close()
		time.Sleep(200 * time.Millisecond) // дочитать вывод
		if err != nil {
			m.add("команда завершилась с ошибкой: " + err.Error())
			m.finish(fmt.Errorf("команда завершилась с кодом %s", exitCode(err)))
			return
		}
		m.add("готово")
		m.finish(nil)
	}()
	return nil
}

func exitCode(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return strconv.Itoa(ee.ExitCode())
	}
	return err.Error()
}

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// pickAssets выбирает из релиза пакеты нужного формата (ext: ".ipk" или ".apk")
// нужен только основной пакет podkop (без luci-app и языковых пакетов).
func pickAssets(assets []ghAsset, ext string) ([]ghAsset, error) {
	var out []ghAsset
	for _, pre := range []string{"podkop-"} {
		found := false
		for _, a := range assets {
			if strings.HasPrefix(a.Name, pre) && strings.HasSuffix(a.Name, ext) {
				out, found = append(out, a), true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("в релизе нет пакета %s*%s", pre, ext)
		}
	}
	return out, nil
}

func download(ctx context.Context, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// installLatest скачивает пакеты последнего релиза с GitHub и ставит их менеджером
// пакетов; зависимости (sing-box и др.) подтягиваются из репозиториев системы.
func (m *Manager) installLatest() error {
	if err := m.begin("Установка Podkop"); err != nil {
		return err
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		pm, ext := pkgManager(), ".ipk"
		if pm == "apk" {
			ext = ".apk"
		}
		m.add("запрос последнего релиза: " + latestURL)
		req, _ := http.NewRequestWithContext(ctx, "GET", latestURL, nil)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			m.finish(fmt.Errorf("GitHub недоступен: %w (попробуйте установку через зеркало)", err))
			return
		}
		var rel struct {
			Tag    string    `json:"tag_name"`
			Assets []ghAsset `json:"assets"`
		}
		err = json.NewDecoder(resp.Body).Decode(&rel)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			m.finish(fmt.Errorf("не удалось получить релиз (HTTP %d)", resp.StatusCode))
			return
		}
		pick, err := pickAssets(rel.Assets, ext)
		if err != nil {
			m.finish(err)
			return
		}
		m.add("последняя версия: " + rel.Tag)
		dir, err := os.MkdirTemp("", "podkop-")
		if err != nil {
			m.finish(err)
			return
		}
		defer os.RemoveAll(dir)
		var files []string
		for _, a := range pick {
			m.add("скачиваю " + a.Name)
			dst := filepath.Join(dir, a.Name)
			if err := download(ctx, a.URL, dst); err != nil {
				m.finish(fmt.Errorf("%s: %w", a.Name, err))
				return
			}
			files = append(files, "'"+dst+"'")
		}
		var shell string
		if pm == "apk" {
			shell = "apk update; apk add --allow-untrusted " + strings.Join(files, " ")
		} else {
			shell = "opkg update; opkg install " + strings.Join(files, " ")
		}
		m.add("$ " + shell)
		cmd := exec.CommandContext(ctx, "sh", "-c", shell)
		pr, pw := io.Pipe()
		cmd.Stdout, cmd.Stderr = pw, pw
		if err := cmd.Start(); err != nil {
			m.finish(err)
			return
		}
		go func() {
			sc := bufio.NewScanner(pr)
			for sc.Scan() {
				m.add(sc.Text())
			}
		}()
		err = cmd.Wait()
		_ = pw.Close()
		time.Sleep(200 * time.Millisecond)
		if err != nil {
			m.finish(fmt.Errorf("установка пакетов завершилась с кодом %s", exitCode(err)))
			return
		}
		m.add("готово: Podkop " + rel.Tag)
		m.finish(nil)
	}()
	return nil
}
