// Package kmods проверяет и устанавливает модули ядра, нужные режимам TUN и TPROXY на OpenWrt
// (kmod-tun и kmod-nft-tproxy) через менеджер пакетов opkg или apk.
package kmods

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"corepanel/internal/platform"
)

// Packages — пакеты ядерных модулей.
var Packages = []string{"kmod-tun", "kmod-nft-tproxy"}

// Job — состояние установки.
type Job struct {
	Running  bool     `json:"running"`
	Finished bool     `json:"finished"`
	Error    string   `json:"error,omitempty"`
	Output   []string `json:"output"`
}

// Status — какие модули есть и можно ли их поставить.
type Status struct {
	Installable bool   `json:"installable"` // OpenWrt и есть opkg/apk
	Manager     string `json:"manager,omitempty"`
	TUN         bool   `json:"tun"`
	TProxy      bool   `json:"tproxy"`
	Command     string `json:"command"`
	Job         Job    `json:"job"`
}

// Manager запускает установку (одновременно не более одной).
type Manager struct {
	Info platform.Info
	mu   sync.Mutex
	job  Job
}

func New(info platform.Info) *Manager { return &Manager{Info: info} }

func manager() string {
	for _, dir := range []string{"/opt/bin", "/opt/sbin"} {
		if cur := os.Getenv("PATH"); !strings.Contains(cur, dir) {
			_ = os.Setenv("PATH", cur+":"+dir)
		}
	}
	if _, err := exec.LookPath("opkg"); err == nil {
		return "opkg"
	}
	if _, err := exec.LookPath("apk"); err == nil {
		return "apk"
	}
	return ""
}

func moduleLoaded(names ...string) bool {
	b, _ := os.ReadFile("/proc/modules")
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		for _, n := range names {
			if len(f) > 0 && f[0] == n {
				return true
			}
		}
	}
	for _, n := range names {
		if _, err := os.Stat("/sys/module/" + n); err == nil { // загружен или встроен в ядро
			return true
		}
	}
	return false
}

func tunOpens() bool {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func pkgInstalled(mgr, pkg string) bool {
	switch mgr {
	case "opkg":
		out, err := exec.Command("opkg", "list-installed", pkg).Output()
		return err == nil && strings.HasPrefix(string(out), pkg+" ")
	case "apk":
		return exec.Command("apk", "info", "-e", pkg).Run() == nil
	}
	return false
}

// Check возвращает состояние модулей. На не-OpenWrt системах Installable=false, а TUN/TProxy
// определяются только по самой системе.
func (m *Manager) Check() Status {
	mgr := manager()
	st := Status{Manager: mgr}
	st.Installable = m.Info.OS == platform.OpenWrt && mgr != ""
	st.TUN = tunOpens() || moduleLoaded("tun")
	st.TProxy = moduleLoaded("nft_tproxy", "xt_TPROXY")
	if mgr == "apk" {
		st.Command = "apk update && apk add " + strings.Join(Packages, " ")
	} else {
		st.Command = "opkg update && opkg install " + strings.Join(Packages, " ")
	}
	m.mu.Lock()
	st.Job = Job{Running: m.job.Running, Finished: m.job.Finished, Error: m.job.Error, Output: append([]string{}, m.job.Output...)}
	m.mu.Unlock()
	return st
}

// Install ставит пакеты и подгружает модули. Возвращает false, если установка уже идёт.
func (m *Manager) Install() (bool, string) {
	mgr := manager()
	if m.Info.OS != platform.OpenWrt || mgr == "" {
		return false, "установка модулей ядра доступна только на OpenWrt с opkg или apk"
	}
	m.mu.Lock()
	if m.job.Running {
		m.mu.Unlock()
		return false, "установка уже идёт"
	}
	m.job = Job{Running: true}
	m.mu.Unlock()
	go m.run(mgr)
	return true, ""
}

func (m *Manager) add(l string) {
	m.mu.Lock()
	m.job.Output = append(m.job.Output, l)
	if len(m.job.Output) > 300 {
		m.job.Output = m.job.Output[len(m.job.Output)-300:]
	}
	m.mu.Unlock()
}

func (m *Manager) exec(ctx context.Context, name string, args ...string) error {
	m.add("$ " + name + " " + strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	r, w, _ := os.Pipe()
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		w.Close()
		r.Close()
		return err
	}
	w.Close()
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		m.add(sc.Text())
	}
	r.Close()
	return cmd.Wait()
}

func (m *Manager) run(mgr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var err error
	if mgr == "apk" {
		if err = m.exec(ctx, "apk", "update"); err == nil {
			err = m.exec(ctx, "apk", append([]string{"add"}, Packages...)...)
		}
	} else if err = m.exec(ctx, "opkg", "update"); err == nil {
		err = m.exec(ctx, "opkg", append([]string{"install"}, Packages...)...)
	}
	if err == nil {
		for _, mod := range []string{"tun", "nft_tproxy"} {
			if p, e := exec.LookPath("modprobe"); e == nil {
				_ = m.exec(ctx, p, mod)
			}
		}
	}
	m.mu.Lock()
	m.job.Running, m.job.Finished = false, true
	if err != nil {
		m.job.Error = "установка не удалась: " + err.Error() + ". Ядро прошивки должно совпадать с версией репозитория: при несовпадении поставьте модули вручную после обновления прошивки"
	}
	m.mu.Unlock()
}
