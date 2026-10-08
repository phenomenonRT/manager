// Package platform определяет окружение: OpenWrt, Keenetic (Entware) или обычный Linux.
package platform

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	OpenWrt  = "openwrt"
	Keenetic = "keenetic"
	Linux    = "linux"
)

// Info — сведения о системе.
type Info struct {
	OS         string   `json:"os"`
	OSName     string   `json:"os_name"`
	Arch       string   `json:"arch"`    // ключ архитектуры для выбора релиза: amd64 arm64 armv7 mipsle …
	Machine    string   `json:"machine"` // вывод uname -m
	DataDir    string   `json:"data_dir"`
	BinDir     string   `json:"bin_dir"`
	LANIface   string   `json:"lan_iface"`
	FirewallBE string   `json:"firewall_backend"` // nft | iptables | ""
	MemTotalMB int      `json:"mem_total_mb"`
	BinFreeMB  int      `json:"bin_free_mb"`
	Notes      []string `json:"notes"`
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func readFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

// Detect определяет платформу. Переменные окружения COREPANEL_PLATFORM,
// COREPANEL_DIR и COREPANEL_BIN_DIR переопределяют результат.
func Detect() Info {
	in := Info{OS: Linux, OSName: "Linux"}
	in.Machine = machine()
	in.Arch = archKey(in.Machine)

	osr := readFile("/etc/os-release")
	switch {
	case exists("/etc/openwrt_release") || strings.Contains(osr, "ID=\"openwrt\"") || strings.Contains(osr, "ID=openwrt"):
		in.OS, in.OSName = OpenWrt, "OpenWrt"
		if rel := readFile("/etc/openwrt_release"); rel != "" {
			for _, l := range strings.Split(rel, "\n") {
				if strings.HasPrefix(l, "DISTRIB_DESCRIPTION=") {
					in.OSName = strings.Trim(strings.TrimPrefix(l, "DISTRIB_DESCRIPTION="), "'\"")
				}
			}
		}
	case isKeenetic():
		in.OS, in.OSName = Keenetic, "Keenetic (Entware)"
	}
	if v := os.Getenv("COREPANEL_PLATFORM"); v == OpenWrt || v == Keenetic || v == Linux {
		in.OS = v
	}

	switch in.OS {
	case Keenetic:
		in.DataDir = "/opt/etc/corepanel"
		in.BinDir = "/opt/sbin"
		in.LANIface = firstExisting("br0", "br-lan")
	case OpenWrt:
		in.DataDir = "/etc/corepanel"
		in.BinDir = "/etc/corepanel/bin"
		if mounted("/opt") && writable("/opt") {
			in.BinDir = "/opt/corepanel/bin"
		}
		in.LANIface = firstExisting("br-lan", "br0")
	default:
		if os.Geteuid() == 0 {
			in.DataDir = "/etc/corepanel"
			in.BinDir = "/etc/corepanel/bin"
		} else {
			home, _ := os.UserHomeDir()
			in.DataDir = filepath.Join(home, ".corepanel")
			in.BinDir = filepath.Join(in.DataDir, "bin")
		}
		in.LANIface = firstExisting("br-lan", "br0")
	}
	if v := os.Getenv("COREPANEL_DIR"); v != "" {
		in.DataDir = v
		if os.Getenv("COREPANEL_BIN_DIR") == "" {
			in.BinDir = filepath.Join(v, "bin")
		}
	}
	if v := os.Getenv("COREPANEL_BIN_DIR"); v != "" {
		in.BinDir = v
	}

	in.FirewallBE = detectFirewall(in.OS)
	in.MemTotalMB = memTotalMB()
	in.BinFreeMB = int(FreeBytes(nearestExisting(in.BinDir)) / (1 << 20))
	in.Notes = notes(in)
	return in
}

func isKeenetic() bool {
	for _, p := range []string{"/bin/ndmc", "/usr/bin/ndmc", "/opt/bin/ndmc", "/etc/ndm"} {
		if exists(p) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(readFile("/proc/version")), "keenetic")
}

func firstExisting(names ...string) string {
	for _, n := range names {
		if _, err := net.InterfaceByName(n); err == nil {
			return n
		}
	}
	return names[0]
}

func mounted(dir string) bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) > 1 && fs[1] == dir {
			return true
		}
	}
	return false
}

func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".w")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

func nearestExisting(p string) string {
	for p != "/" && p != "." && !exists(p) {
		p = filepath.Dir(p)
	}
	return p
}

func memTotalMB() int {
	for _, l := range strings.Split(readFile("/proc/meminfo"), "\n") {
		if strings.HasPrefix(l, "MemTotal:") {
			f := strings.Fields(l)
			if len(f) >= 2 {
				kb, _ := strconv.Atoi(f[1])
				return kb / 1024
			}
		}
	}
	return 0
}

func detectFirewall(osName string) string {
	_, nftErr := exec.LookPath("nft")
	_, ipt := exec.LookPath("iptables")
	switch osName {
	case Keenetic:
		if ipt == nil {
			return "iptables"
		}
		if nftErr == nil {
			return "nft"
		}
	default:
		if nftErr == nil {
			return "nft"
		}
		if ipt == nil {
			return "iptables"
		}
	}
	return ""
}

// archKey переводит вывод uname -m в ключ, по которому подбирается релиз ядра.
func archKey(machine string) string {
	m := strings.ToLower(machine)
	switch {
	case m == "x86_64" || m == "amd64":
		return "amd64"
	case m == "aarch64" || m == "arm64" || m == "armv8l":
		if runtime.GOARCH == "arm" {
			return "armv7"
		}
		return "arm64"
	case strings.HasPrefix(m, "armv7"):
		return "armv7"
	case strings.HasPrefix(m, "armv6"):
		return "armv6"
	case strings.HasPrefix(m, "armv5"):
		return "armv5"
	case m == "i386" || m == "i486" || m == "i586" || m == "i686":
		return "386"
	case m == "mips64":
		return "mips64"
	case m == "mips64el":
		return "mips64le"
	case m == "mips":
		if runtime.GOARCH == "mipsle" {
			return "mipsle"
		}
		return "mips"
	case m == "mipsel":
		return "mipsle"
	case m == "riscv64":
		return "riscv64"
	}
	switch runtime.GOARCH {
	case "arm":
		return "armv7"
	case "mipsle":
		return "mipsle"
	}
	return runtime.GOARCH
}

func notes(in Info) []string {
	var n []string
	if in.FirewallBE == "" {
		n = append(n, "Не найдены ни nft, ни iptables: режимы redirect/tproxy недоступны, используйте TUN.")
	}
	if in.BinFreeMB > 0 && in.BinFreeMB < 70 {
		n = append(n, "В каталоге для бинарников свободно меньше 70 МБ — ядро (30–40 МБ) может не поместиться. Подключите USB-накопитель и задайте каталог в разделе «Ядро».")
	}
	if in.MemTotalMB > 0 && in.MemTotalMB < 128 {
		n = append(n, "Мало оперативной памяти (<128 МБ): Mihomo и sing-box будут работать, но избегайте больших наборов правил и режима fakeip с большим числом клиентов.")
	}
	switch in.OS {
	case Keenetic:
		n = append(n, "Keenetic: нужен компонент «Пакеты OPKG» с установленным Entware. Поддержка TUN и TPROXY зависит от модели и версии прошивки — при недоступности используйте режим redirect (iptables).")
	case OpenWrt:
		n = append(n, "OpenWrt: для режимов TUN/TPROXY нужны модули ядра kmod-tun и kmod-nft-tproxy (opkg install kmod-tun kmod-nft-tproxy).")
	}
	return n
}
