// Package installer скачивает и устанавливает ядра sing-box и Mihomo с GitHub Releases.
package installer

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"corepanel/internal/model"
	"corepanel/internal/platform"
)

// Repo — репозиторий релизов ядра.
var Repo = map[string]string{
	model.CoreSingbox: "SagerNet/sing-box",
	model.CoreMihomo:  "MetaCubeX/mihomo",
	model.CoreAmnezia: "phenomenonRT/amnezia-box",
}

// NeedMB — сколько места занимает распакованное ядро (оценка, МБ). Панель блокирует
// установку с GitHub, если свободного места меньше.
var NeedMB = map[string]int{model.CoreSingbox: 50, model.CoreMihomo: 35, model.CoreAmnezia: 15}

// InstalledMB — размер уже скачанной панелью копии ядра в каталоге установки (МБ): при обновлении это место освободится.
func (in *Installer) InstalledMB(core string, d model.Download) int {
	if st, err := os.Stat(filepath.Join(in.BinDir(d), BinName(core))); err == nil {
		return int(st.Size() >> 20)
	}
	return 0
}

// BinName — имя исполняемого файла.
func BinName(core string) string {
	switch core {
	case model.CoreMihomo:
		return "mihomo"
	case model.CoreAmnezia:
		return "amnezia-box"
	}
	return "sing-box"
}

// variants — допустимые обозначения архитектуры в именах релизных файлов (по приоритету).
var variants = map[string]map[string][]string{
	model.CoreSingbox: {
		"amd64":    {"amd64", "amd64-musl", "amd64-glibc"},
		"arm64":    {"arm64", "arm64-musl", "arm64-glibc"},
		"armv7":    {"armv7", "armv7-musl", "armv7-glibc"},
		"armv6":    {"armv6", "armv6-musl", "armv6-glibc"},
		"386":      {"386", "386-musl", "386-glibc"},
		"mips64le": {"mips64le", "mips64le-musl"},
		"mipsle":   {"mipsle", "mipsle-softfloat", "mipsle-musl"},
		"mips":     {"mips", "mips-softfloat"},
		"riscv64":  {"riscv64", "riscv64-musl"},
	},
	// amnezia-box: готовые бинарники без архива; основная сборка сжата UPX (мала), «-plain» — запасная без сжатия
	model.CoreAmnezia: {
		"arm64":  {"arm64", "arm64-plain"},
		"armv7":  {"armv7", "armv7-plain"},
		"armv6":  {"armv5", "armv5-plain"},
		"armv5":  {"armv5", "armv5-plain"},
		"mipsle": {"mipsel", "mipsel-plain"},
		"mips":   {"mips", "mips-plain"},
	},
	model.CoreMihomo: {
		"amd64":    {"amd64", "amd64-compatible", "amd64-v1"},
		"arm64":    {"arm64"},
		"armv7":    {"armv7"},
		"armv6":    {"armv6", "armv5"},
		"armv5":    {"armv5"},
		"386":      {"386", "386-softfloat"},
		"mips64":   {"mips64"},
		"mips64le": {"mips64le"},
		"mipsle":   {"mipsle-softfloat", "mipsle-hardfloat"},
		"mips":     {"mips-softfloat", "mips-hardfloat"},
		"riscv64":  {"riscv64"},
	},
}

var (
	reSingbox = regexp.MustCompile(`^sing-box-[0-9][^/]*?-linux-(.+)\.tar\.gz$`)
	reAmnezia = regexp.MustCompile(`^amnezia-box-linux-([a-z0-9]+(?:-plain)?)$`)
	reMihomo  = regexp.MustCompile(`^mihomo-linux-(.+?)-(?:v[0-9]+\.[0-9]+\.[0-9]+|alpha-[0-9a-f]+).*\.gz$`)
)

func assetVariant(core, name string) (string, bool) {
	var m []string
	if core == model.CoreAmnezia {
		m = reAmnezia.FindStringSubmatch(name)
	} else if core == model.CoreSingbox {
		m = reSingbox.FindStringSubmatch(name)
	} else {
		if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".zip") {
			return "", false
		}
		m = reMihomo.FindStringSubmatch(name)
	}
	if m == nil {
		return "", false
	}
	return m[1], true
}

// PickAssets возвращает подходящие архитектуре релизные файлы по убыванию приоритета
// (сначала статическая сборка, затем musl и glibc): если первая не запустится, пробуем следующую.
func PickAssets(core, arch string, names []string) ([]string, error) {
	want, ok := variants[core][arch]
	if !ok {
		return nil, fmt.Errorf("архитектура «%s» не поддерживается установщиком", arch)
	}
	have := map[string]string{}
	for _, n := range names {
		if v, ok := assetVariant(core, n); ok {
			if _, dup := have[v]; !dup {
				have[v] = n
			}
		}
	}
	var out []string
	for _, w := range want {
		if n, ok := have[w]; ok {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("в релизе нет сборки %s для архитектуры «%s»", BinName(core), arch)
	}
	return out, nil
}

// PickAsset выбирает самый предпочтительный файл.
func PickAsset(core, arch string, names []string) (string, error) {
	all, err := PickAssets(core, arch, names)
	if err != nil {
		return "", err
	}
	return all[0], nil
}

// NoBuildHint — подсказка, если готовой сборки нет.
func NoBuildHint(core string, osName string) string {
	switch osName {
	case platform.OpenWrt:
		return fmt.Sprintf("Установите пакет из репозитория: opkg update && opkg install %s — затем укажите путь к бинарнику в разделе «Компоненты».", BinName(core))
	case platform.Keenetic:
		return fmt.Sprintf("Попробуйте пакет Entware: opkg update && opkg install %s — затем укажите путь к бинарнику в разделе «Компоненты».", BinName(core))
	}
	return "Соберите ядро самостоятельно или укажите путь к своему бинарнику в разделе «Компоненты»."
}

// ---------- задача установки ----------

// Job — состояние установки (опрашивается из UI).
type Job struct {
	mu       sync.Mutex
	Core     string  `json:"core"`
	Stage    string  `json:"stage"` // idle | resolve | download | extract | verify | done | error
	Message  string  `json:"message"`
	Percent  float64 `json:"percent"`
	Version  string  `json:"version"`
	Error    string  `json:"error"`
	Running  bool    `json:"running"`
	Finished bool    `json:"finished"`
}

func (j *Job) set(f func(j *Job)) { j.mu.Lock(); f(j); j.mu.Unlock() }

// Snapshot — копия состояния без мьютекса.
func (j *Job) Snapshot() Job {
	j.mu.Lock()
	defer j.mu.Unlock()
	return Job{Core: j.Core, Stage: j.Stage, Message: j.Message, Percent: j.Percent, Version: j.Version,
		Error: j.Error, Running: j.Running, Finished: j.Finished}
}

// Installer выполняет установку ядер.
type Installer struct {
	Info platform.Info
	Job  Job
	mu   sync.Mutex
}

func New(info platform.Info) *Installer { return &Installer{Info: info} }

// BinDir — каталог установки с учётом настроек.
func (in *Installer) BinDir(d model.Download) string {
	if d.BinDir != "" {
		return d.BinDir
	}
	return in.Info.BinDir
}

// Locate ищет бинарник ядра: свой путь → каталог установки → PATH.
func (in *Installer) Locate(core string, d model.Download) string {
	custom := d.SingboxPath
	switch core {
	case model.CoreMihomo:
		custom = d.MihomoPath
	case model.CoreAmnezia:
		custom = d.AmneziaPath
	}
	if custom != "" && isExec(custom) {
		return custom
	}
	if p := filepath.Join(in.BinDir(d), BinName(core)); isExec(p) {
		return p
	}
	if p, err := exec.LookPath(BinName(core)); err == nil {
		return p
	}
	return ""
}

func isExec(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

var reVer = regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.\-+]*)`)

// Version запрашивает версию у бинарника.
func Version(ctx context.Context, core, bin string) (string, error) {
	arg := "version"
	if core == model.CoreMihomo {
		arg = "-v"
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, arg).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s не запускается: %v (%s)", filepath.Base(bin), err, strings.TrimSpace(firstLine(string(out))))
	}
	line := firstLine(string(out))
	if m := reVer.FindStringSubmatch(line); m != nil {
		return m[1], nil
	}
	return strings.TrimSpace(line), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ---------- сеть ----------

func httpClient(d model.Download) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if d.Proxy != "" {
		pu, err := url.Parse(d.Proxy)
		if err != nil || pu.Host == "" {
			return nil, fmt.Errorf("неверный адрес прокси «%s»", d.Proxy)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{Transport: tr, Timeout: 0}, nil
}

func withMirror(d model.Download, u string) string {
	if m := strings.TrimSpace(d.Mirror); m != "" {
		return strings.TrimRight(m, "/") + "/" + u
	}
	return u
}

type release struct {
	Tag    string `json:"tag_name"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

func getJSON(ctx context.Context, c *http.Client, u string, v any) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "corepanel")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v)
}

// ResolveLatestTag узнаёт последнюю версию без API: по редиректу /releases/latest.
func resolveLatestTag(ctx context.Context, c *http.Client, d model.Download, repo string) (string, error) {
	cc := *c
	cc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, _ := http.NewRequestWithContext(ctx, "HEAD", withMirror(d, "https://github.com/"+repo+"/releases/latest"), nil)
	req.Header.Set("User-Agent", "corepanel")
	resp, err := cc.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if i := strings.LastIndex(loc, "/tag/"); i >= 0 {
		return path.Base(loc[i+5:]), nil
	}
	return "", fmt.Errorf("не удалось определить последнюю версию (HTTP %d)", resp.StatusCode)
}

type target struct {
	URL     string
	Name    string
	Size    int64
	Version string
}

// resolve находит файл для загрузки: сначала через GitHub API, затем по шаблону имени.
func (in *Installer) resolve(ctx context.Context, c *http.Client, d model.Download, core, version string) ([]target, error) {
	repo := Repo[core]
	api := "https://api.github.com/repos/" + repo + "/releases/latest"
	if version != "" {
		tag := version
		if core == model.CoreMihomo && !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		if core == model.CoreSingbox && !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		api = "https://api.github.com/repos/" + repo + "/releases/tags/" + tag
	}
	var rel release
	apiErr := getJSON(ctx, c, api, &rel)
	if apiErr == nil && len(rel.Assets) > 0 {
		var names []string
		for _, a := range rel.Assets {
			names = append(names, a.Name)
		}
		picked, err := PickAssets(core, in.Info.Arch, names)
		if err != nil {
			return nil, fmt.Errorf("%v. %s", err, NoBuildHint(core, in.Info.OS))
		}
		var out []target
		for _, name := range picked {
			for _, a := range rel.Assets {
				if a.Name == name {
					out = append(out, target{URL: withMirror(d, a.URL), Name: name, Size: a.Size, Version: strings.TrimPrefix(rel.Tag, "v")})
				}
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}

	// запасной путь: GitHub API недоступен — собираем ссылку по шаблону
	tag := version
	if tag == "" {
		t, err := resolveLatestTag(ctx, c, d, repo)
		if err != nil {
			return nil, fmt.Errorf("GitHub недоступен (API: %v; редирект: %v). Задайте зеркало или прокси в разделе «Компоненты»", apiErr, err)
		}
		tag = t
	}
	if core != model.CoreAmnezia && !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	ver := strings.TrimPrefix(tag, "v")
	var out []target
	for _, v := range variants[core][in.Info.Arch] {
		var name string
		if core == model.CoreAmnezia {
			name = "amnezia-box-linux-" + v
		} else if core == model.CoreSingbox {
			name = fmt.Sprintf("sing-box-%s-linux-%s.tar.gz", ver, v)
		} else {
			name = fmt.Sprintf("mihomo-linux-%s-%s.gz", v, tag)
		}
		u := withMirror(d, fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, tag, name))
		req, _ := http.NewRequestWithContext(ctx, "HEAD", u, nil)
		req.Header.Set("User-Agent", "corepanel")
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			out = append(out, target{URL: u, Name: name, Size: resp.ContentLength, Version: ver})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("не найден файл релиза %s для архитектуры «%s». %s", BinName(core), in.Info.Arch, NoBuildHint(core, in.Info.OS))
	}
	return out, nil
}

// ---------- установка ----------

// Start запускает установку с GitHub в фоне. Возвращает ошибку, если установка уже идёт.
func (in *Installer) Start(core, version string, d model.Download) error {
	return in.run(core, func(ctx context.Context) (string, error) { return in.install(ctx, core, version, d) })
}

// StartPackage устанавливает ядро из репозитория пакетов системы (opkg/apk).
// Пакеты OpenWrt и Entware собраны компактнее релизов GitHub — это выход, когда мало флеш-памяти.
func (in *Installer) StartPackage(core string) error {
	if core == model.CoreAmnezia {
		return errors.New("amnezia-box нет в репозиториях пакетов — установите его с GitHub (сборка сжата и занимает около 15 МБ)")
	}
	return in.run(core, func(ctx context.Context) (string, error) { return in.installPackage(ctx, core) })
}

func (in *Installer) run(core string, f func(ctx context.Context) (string, error)) error {
	if core != model.CoreSingbox && core != model.CoreMihomo && core != model.CoreAmnezia {
		return fmt.Errorf("неизвестное ядро «%s»", core)
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.Job.Snapshot().Running {
		return errors.New("установка уже выполняется")
	}
	in.Job.set(func(j *Job) {
		// поля задаём по одному: присваивание всей структуры затёрло бы захваченный мьютекс
		j.Core, j.Stage, j.Message, j.Percent = core, "resolve", "Определяю версию…", 0
		j.Version, j.Error, j.Running, j.Finished = "", "", true, false
	})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		ver, err := f(ctx)
		in.Job.set(func(j *Job) {
			j.Running, j.Finished = false, true
			if err != nil {
				j.Stage, j.Error, j.Message = "error", err.Error(), "Ошибка установки"
			} else {
				j.Stage, j.Percent, j.Version, j.Message = "done", 100, ver, "Установлено: "+ver
			}
		})
	}()
	return nil
}

func isNoSpace(err error) bool { return errors.Is(err, syscall.ENOSPC) }

// notRunnable — скачанный файл не запускается (не тот загрузчик/архитектура): можно пробовать другую сборку.
type notRunnable struct{ error }

// install скачивает релиз и распаковывает его прямо из потока: архив на диск не пишется,
// поэтому во время установки занято место только под сам бинарник.
// Если сборка не запускается (например, glibc на musl-системе), пробуется следующая.
func (in *Installer) install(ctx context.Context, core, version string, d model.Download) (string, error) {
	c, err := httpClient(d)
	if err != nil {
		return "", err
	}
	tgs, err := in.resolve(ctx, c, d, core, version)
	if err != nil {
		return "", err
	}
	binDir := in.BinDir(d)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", fmt.Errorf("не удалось создать каталог %s: %v", binDir, err)
	}
	var fails []string
	for _, tg := range tgs {
		ver, err := in.installOne(ctx, c, core, tg, binDir)
		if err == nil {
			return ver, nil
		}
		var nr notRunnable
		if !errors.As(err, &nr) {
			return "", err
		}
		fails = append(fails, tg.Name+": "+err.Error())
		in.Job.set(func(j *Job) {
			j.Message, j.Percent = "Сборка не запускается, пробую другую…", 0
		})
	}
	return "", fmt.Errorf("ни одна из сборок не запустилась на этой системе (архитектура «%s»). %s. "+
		"Попробуйте «Из пакетов системы» или укажите свой бинарник в разделе «Компоненты»", in.Info.Arch, strings.Join(fails, "; "))
}

func (in *Installer) installOne(ctx context.Context, c *http.Client, core string, tg target, binDir string) (string, error) {
	final := filepath.Join(binDir, BinName(core))
	newBin := final + ".new"
	// остатки прошлых попыток и старые копии занимают место зря
	_ = os.Remove(newBin)
	_ = os.Remove(final + ".bak")
	if m, _ := filepath.Glob(filepath.Join(binDir, ".dl-*")); len(m) > 0 {
		for _, f := range m {
			_ = os.Remove(f)
		}
	}
	// после распаковки ядро занимает примерно 2,5 размера архива; жёсткий минимум — 1,5
	need := uint64(tg.Size) * 3 / 2
	if core == model.CoreAmnezia {
		need = uint64(tg.Size) * 11 / 10 // бинарник качается как есть, без распаковки
	}
	if free := platform.FreeBytes(binDir); free > 0 && tg.Size > 0 && free < need {
		return "", fmt.Errorf("в %s свободно %d МБ — слишком мало (размер загрузки %d МБ, после распаковки ядро занимает около %d МБ). "+
			"Подключите накопитель и задайте каталог в разделе «Компоненты» либо установите ядро из пакетов системы",
			binDir, free>>20, tg.Size>>20, (tg.Size*5/2)>>20)
	}

	in.Job.set(func(j *Job) { j.Stage, j.Message = "download", "Скачиваю и распаковываю "+tg.Name })
	err := in.fetchExtract(ctx, c, tg, core, newBin)
	if isNoSpace(err) {
		if _, serr := os.Stat(final); serr == nil {
			// старая и новая версии вместе не помещаются — освобождаем место старой и пробуем ещё раз
			in.Job.set(func(j *Job) {
				j.Message, j.Percent = "Места мало — удаляю старую версию и повторяю загрузку", 0
			})
			_ = os.Remove(newBin)
			_ = os.Remove(final)
			err = in.fetchExtract(ctx, c, tg, core, newBin)
		}
	}
	if err != nil {
		_ = os.Remove(newBin)
		if isNoSpace(err) {
			return "", fmt.Errorf("в %s не хватило места для ядра. Подключите накопитель и задайте каталог в разделе «Компоненты» либо установите ядро из пакетов системы", binDir)
		}
		return "", err
	}
	if err := os.Chmod(newBin, 0o755); err != nil {
		return "", err
	}

	in.Job.set(func(j *Job) { j.Stage, j.Message, j.Percent = "verify", "Проверяю запуск…", 95 })
	ver, err := Version(ctx, core, newBin)
	if err != nil {
		why := DiagnoseBinary(newBin)
		_ = os.Remove(newBin)
		return "", notRunnable{fmt.Errorf("файл не запускается: %s", why)}
	}
	if err := os.Rename(newBin, final); err != nil {
		return "", err
	}
	return ver, nil
}

// DiagnoseBinary объясняет, почему ELF-файл не запускается: чужая архитектура или нет загрузчика.
func DiagnoseBinary(path string) string {
	f, err := elf.Open(path)
	if err != nil {
		return "это не исполняемый ELF-файл (" + err.Error() + ")"
	}
	defer f.Close()
	arch := f.Machine.String()
	bits := "32-бит"
	if f.Class == elf.ELFCLASS64 {
		bits = "64-бит"
	}
	if s := f.Section(".interp"); s != nil {
		if b, err := s.Data(); err == nil {
			interp := strings.TrimRight(string(b), "\x00")
			if _, err := os.Stat(interp); err != nil {
				return fmt.Sprintf("сборка %s %s динамическая и требует загрузчик %s, которого нет в системе (glibc-сборка на musl/uClibc?)", arch, bits, interp)
			}
			return fmt.Sprintf("сборка %s %s не запустилась, хотя загрузчик %s есть — вероятно, не хватает библиотек", arch, bits, interp)
		}
	}
	return fmt.Sprintf("статическая сборка %s %s не запустилась — вероятно, она не подходит процессору или ядру системы (проверьте `uname -m`)", arch, bits)
}

type progressWriter struct {
	in    *Installer
	total int64
	done  int64
	last  time.Time
}

func (p *progressWriter) Write(b []byte) (int, error) {
	p.done += int64(len(b))
	if time.Since(p.last) > 300*time.Millisecond {
		p.last = time.Now()
		pct := 0.0
		if p.total > 0 {
			pct = float64(p.done) / float64(p.total) * 90
		}
		p.in.Job.set(func(j *Job) {
			j.Percent = pct
			j.Message = fmt.Sprintf("Скачано %.1f МБ", float64(p.done)/(1<<20))
		})
	}
	return len(b), nil
}

// fetchExtract качает архив и пишет распакованный бинарник в dst (sing-box: tar.gz, Mihomo: gz).
func (in *Installer) fetchExtract(ctx context.Context, c *http.Client, tg target, core, dst string) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", tg.URL, nil)
	req.Header.Set("User-Agent", "corepanel")
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("загрузка не удалась: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("загрузка не удалась: HTTP %d", resp.StatusCode)
	}
	total := resp.ContentLength
	if total <= 0 {
		total = tg.Size
	}
	body := io.TeeReader(resp.Body, &progressWriter{in: in, total: total})
	if core == model.CoreAmnezia {
		return writeRaw(body, dst)
	}
	gz, err := gzip.NewReader(body)
	if err != nil {
		return fmt.Errorf("архив повреждён: %v", err)
	}
	defer gz.Close()

	var src io.Reader = gz
	if core == model.CoreSingbox {
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				return errors.New("в архиве нет файла sing-box")
			}
			if err != nil {
				return fmt.Errorf("обрыв загрузки или архив повреждён: %v", err)
			}
			if h.Typeflag == tar.TypeReg && path.Base(h.Name) == "sing-box" {
				src = tr
				break
			}
		}
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		if isNoSpace(err) {
			return err
		}
		return fmt.Errorf("обрыв загрузки: %v", err)
	}
	return out.Close()
}

// writeRaw сохраняет бинарник, скачанный без архива (amnezia-box), проверив ELF-заголовок:
// страница ошибки или зеркало с HTML не должны превратиться в «ядро».
func writeRaw(src io.Reader, dst string) error {
	br := bufio.NewReader(src)
	if magic, err := br.Peek(4); err != nil || string(magic) != "\x7fELF" {
		return errors.New("скачан не исполняемый файл (ожидался ELF): проверьте зеркало и прокси")
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, br); err != nil {
		out.Close()
		if isNoSpace(err) {
			return err
		}
		return fmt.Errorf("обрыв загрузки: %v", err)
	}
	return out.Close()
}

// ---------- установка из пакетов системы ----------

// PackageNames — имена пакетов ядер в репозиториях OpenWrt и Entware (пробуются по порядку).
var PackageNames = map[string][]string{
	model.CoreSingbox: {"sing-box", "sing-box-go"},
	model.CoreMihomo:  {"mihomo", "clash-meta"},
}

func pkgCommands() (update, install []string, err error) {
	for _, dir := range []string{"/opt/bin", "/opt/sbin"} { // Entware
		if cur := os.Getenv("PATH"); !strings.Contains(cur, dir) {
			_ = os.Setenv("PATH", cur+":"+dir)
		}
	}
	if _, e := exec.LookPath("opkg"); e == nil {
		return []string{"opkg", "update"}, []string{"opkg", "install"}, nil
	}
	if _, e := exec.LookPath("apk"); e == nil {
		return []string{"apk", "update"}, []string{"apk", "add"}, nil
	}
	return nil, nil, errors.New("в системе нет opkg или apk — установка из пакетов недоступна")
}

func lastLines(s string, n int) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, " | ")
}

func (in *Installer) installPackage(ctx context.Context, core string) (string, error) {
	upd, ins, err := pkgCommands()
	if err != nil {
		return "", err
	}
	in.Job.set(func(j *Job) {
		j.Stage, j.Message, j.Percent = "download", "Обновляю список пакетов…", 10
	})
	if out, err := exec.CommandContext(ctx, upd[0], upd[1:]...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("%s не смог обновить список пакетов (нет интернета или DNS?): %s", upd[0], lastLines(string(out), 3))
	}
	var lastErr string
	for i, name := range PackageNames[core] {
		in.Job.set(func(j *Job) {
			j.Message, j.Percent = "Устанавливаю пакет "+name+"…", float64(40+i*20)
		})
		out, err := exec.CommandContext(ctx, ins[0], append(append([]string{}, ins[1:]...), name)...).CombinedOutput()
		if err != nil {
			lastErr = fmt.Sprintf("%s: %s", name, lastLines(string(out), 3))
			continue
		}
		bin, lerr := exec.LookPath(BinName(core))
		if lerr != nil {
			lastErr = name + ": пакет установлен, но файл " + BinName(core) + " не найден в PATH"
			continue
		}
		in.Job.set(func(j *Job) { j.Stage, j.Message, j.Percent = "verify", "Проверяю запуск…", 95 })
		ver, verr := Version(ctx, core, bin)
		if verr != nil {
			return "", verr
		}
		return ver + " (из пакета " + name + ")", nil
	}
	return "", fmt.Errorf("пакет ядра не установлен. %s. В репозитории этой системы может не быть такого пакета — тогда используйте установку с GitHub на накопитель", lastLines(lastErr, 1))
}

// Remove удаляет ядро, установленное панелью (каталог установки) и, если оно поставлено
// пакетом системы, сам пакет. Свой бинарник из настроек не трогается.
func (in *Installer) Remove(ctx context.Context, core string, d model.Download) (string, error) {
	if core != model.CoreSingbox && core != model.CoreMihomo && core != model.CoreAmnezia {
		return "", fmt.Errorf("неизвестное ядро «%s»", core)
	}
	if in.Job.Snapshot().Running {
		return "", errors.New("сейчас идёт установка — дождитесь её окончания")
	}
	var done []string
	final := filepath.Join(in.BinDir(d), BinName(core))
	for _, f := range []string{final, final + ".new", final + ".bak"} {
		if err := os.Remove(f); err == nil {
			done = append(done, f)
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("не удалось удалить %s: %v", f, err)
		}
	}
	// ядро из пакета системы (лежит в /usr/bin или /opt/sbin, найдётся через PATH)
	if _, err := exec.LookPath(BinName(core)); err == nil {
		var rm []string
		if _, _, perr := pkgCommands(); perr == nil {
			if _, e := exec.LookPath("opkg"); e == nil {
				rm = []string{"opkg", "remove"}
			} else {
				rm = []string{"apk", "del"}
			}
		}
		if rm != nil {
			for _, name := range PackageNames[core] {
				if err := exec.CommandContext(ctx, rm[0], append(append([]string{}, rm[1:]...), name)...).Run(); err == nil {
					done = append(done, "пакет "+name)
					break
				}
			}
		}
	}
	custom := d.SingboxPath
	switch core {
	case model.CoreMihomo:
		custom = d.MihomoPath
	case model.CoreAmnezia:
		custom = d.AmneziaPath
	}
	if len(done) == 0 {
		if custom != "" && isExec(custom) {
			return "", fmt.Errorf("используется свой бинарник %s — панель его не удаляет; уберите путь в настройках ниже", custom)
		}
		return "", errors.New("нечего удалять: ядро не установлено")
	}
	return strings.Join(done, ", "), nil
}
