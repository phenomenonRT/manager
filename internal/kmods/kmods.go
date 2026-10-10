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
var Packages = []string{"kmod-tun", "kmod-nft-tproxy", "kmod-nft-queue"}

// Job — состояние установки.
type Job struct {
	Title    string   `json:"title,omitempty"`
	Running  bool     `json:"running"`
	Finished bool     `json:"finished"`
	Error    string   `json:"error,omitempty"`
	Output   []string `json:"output"`
}

// Status — какие модули есть и можно ли их поставить.
type Status struct {
	Installable bool     `json:"installable"` // OpenWrt и есть opkg/apk
	Manager     string   `json:"manager,omitempty"`
	TUN         bool     `json:"tun"`
	TProxy      bool     `json:"tproxy"`
	Queue       bool     `json:"queue"` // nfqueue: нужен для auto_redirect в TUN
	Command     string   `json:"command"`
	Present     []string `json:"present"` // какие из Packages установлены менеджером пакетов
	Job         Job      `json:"job"`
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

// QueueAvailable — загружен ли модуль nfqueue (нужен для auto_redirect).
func QueueAvailable() bool { return moduleLoaded("nfnetlink_queue", "nft_queue") }

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
	st.Queue = moduleLoaded("nfnetlink_queue", "nft_queue")
	if mgr == "apk" {
		st.Command = "apk update && apk add " + strings.Join(Packages, " ")
	} else {
		st.Command = "opkg update && opkg install " + strings.Join(Packages, " ")
	}
	st.Present = []string{}
	if mgr != "" {
		for _, p := range Packages {
			if pkgInstalled(mgr, p) {
				st.Present = append(st.Present, p)
			}
		}
	}
	m.mu.Lock()
	st.Job = Job{Title: m.job.Title, Running: m.job.Running, Finished: m.job.Finished, Error: m.job.Error, Output: append([]string{}, m.job.Output...)}
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
	m.job = Job{Running: true, Title: "Установка модулей ядра"}
	m.mu.Unlock()
	go m.run(mgr)
	return true, ""
}

// Remove удаляет установленные пакеты модулей ядра (зависимости TUN и tproxy).
func (m *Manager) Remove() (bool, string) {
	mgr := manager()
	if m.Info.OS != platform.OpenWrt || mgr == "" {
		return false, "удаление доступно только на OpenWrt с opkg или apk"
	}
	var have []string
	for _, p := range Packages {
		if pkgInstalled(mgr, p) {
			have = append(have, p)
		}
	}
	if len(have) == 0 {
		return false, "зависимых компонентов нет: нечего удалять"
	}
	m.mu.Lock()
	if m.job.Running {
		m.mu.Unlock()
		return false, "операция уже идёт"
	}
	m.job = Job{Running: true, Title: "Удаление зависимых компонентов"}
	m.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		var err error
		if mgr == "apk" {
			err = m.exec(ctx, "apk", append([]string{"del"}, have...)...)
		} else {
			err = m.exec(ctx, "opkg", append([]string{"remove"}, have...)...)
		}
		m.mu.Lock()
		m.job.Running, m.job.Finished = false, true
		if err != nil {
			m.job.Error = "удалить не удалось: " + err.Error()
		}
		m.mu.Unlock()
	}()
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
		for _, mod := range []string{"tun", "nft_tproxy", "nfnetlink_queue", "nft_queue"} {
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
