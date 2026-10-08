// Package installer скачивает и устанавливает ядра sing-box и Mihomo с GitHub Releases.
package installer

import (
	"archive/tar"
	"compress/gzip"
	"context"
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
	"time"

	"corepanel/internal/model"
	"corepanel/internal/platform"
)

// Repo — репозиторий релизов ядра.
var Repo = map[string]string{
	model.CoreSingbox: "SagerNet/sing-box",
	model.CoreMihomo:  "MetaCubeX/mihomo",
}

// BinName — имя исполняемого файла.
func BinName(core string) string {
	if core == model.CoreMihomo {
		return "mihomo"
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
	reMihomo  = regexp.MustCompile(`^mihomo-linux-(.+?)-(?:v[0-9]+\.[0-9]+\.[0-9]+|alpha-[0-9a-f]+).*\.gz$`)
)

func assetVariant(core, name string) (string, bool) {
	var m []string
	if core == model.CoreSingbox {
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

// PickAsset выбирает из списка имён релизных файлов подходящий под архитектуру.
func PickAsset(core, arch string, names []string) (string, error) {
	want, ok := variants[core][arch]
	if !ok {
		return "", fmt.Errorf("архитектура «%s» не поддерживается установщиком", arch)
	}
	have := map[string]string{}
	for _, n := range names {
		if v, ok := assetVariant(core, n); ok {
			if _, dup := have[v]; !dup {
				have[v] = n
			}
		}
	}
	for _, w := range want {
		if n, ok := have[w]; ok {
			return n, nil
		}
	}
	return "", fmt.Errorf("в релизе нет сборки %s для архитектуры «%s»", BinName(core), arch)
}

// NoBuildHint — подсказка, если готовой сборки нет.
func NoBuildHint(core string, osName string) string {
	switch osName {
	case platform.OpenWrt:
		return fmt.Sprintf("Установите пакет из репозитория: opkg update && opkg install %s — затем укажите путь к бинарнику в разделе «Ядро».", BinName(core))
	case platform.Keenetic:
		return fmt.Sprintf("Попробуйте пакет Entware: opkg update && opkg install %s — затем укажите путь к бинарнику в разделе «Ядро».", BinName(core))
	}
	return "Соберите ядро самостоятельно или укажите путь к своему бинарнику в разделе «Ядро»."
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
	if core == model.CoreMihomo {
		custom = d.MihomoPath
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
func (in *Installer) resolve(ctx context.Context, c *http.Client, d model.Download, core, version string) (target, error) {
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
		name, err := PickAsset(core, in.Info.Arch, names)
		if err != nil {
			return target{}, fmt.Errorf("%v. %s", err, NoBuildHint(core, in.Info.OS))
		}
		for _, a := range rel.Assets {
			if a.Name == name {
				return target{URL: withMirror(d, a.URL), Name: name, Size: a.Size, Version: strings.TrimPrefix(rel.Tag, "v")}, nil
			}
		}
	}

	// запасной путь: GitHub API недоступен — собираем ссылку по шаблону
	tag := version
	if tag == "" {
		t, err := resolveLatestTag(ctx, c, d, repo)
		if err != nil {
			return target{}, fmt.Errorf("GitHub недоступен (API: %v; редирект: %v). Задайте зеркало или прокси в разделе «Ядро»", apiErr, err)
		}
		tag = t
	}
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	ver := strings.TrimPrefix(tag, "v")
	for _, v := range variants[core][in.Info.Arch] {
		var name string
		if core == model.CoreSingbox {
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
			return target{URL: u, Name: name, Size: resp.ContentLength, Version: ver}, nil
		}
	}
	return target{}, fmt.Errorf("не найден файл релиза %s для архитектуры «%s». %s", BinName(core), in.Info.Arch, NoBuildHint(core, in.Info.OS))
}

// ---------- установка ----------

// Start запускает установку в фоне. Возвращает ошибку, если установка уже идёт.
func (in *Installer) Start(core, version string, d model.Download) error {
	if core != model.CoreSingbox && core != model.CoreMihomo {
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
		ver, err := in.install(ctx, core, version, d)
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

func (in *Installer) install(ctx context.Context, core, version string, d model.Download) (string, error) {
	c, err := httpClient(d)
	if err != nil {
		return "", err
	}
	tg, err := in.resolve(ctx, c, d, core, version)
	if err != nil {
		return "", err
	}
	binDir := in.BinDir(d)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", fmt.Errorf("не удалось создать каталог %s: %v", binDir, err)
	}
	if free := platform.FreeBytes(binDir); free > 0 && tg.Size > 0 && free < uint64(tg.Size)*4 {
		return "", fmt.Errorf("в %s свободно %d МБ — для установки нужно примерно %d МБ. Подключите накопитель и задайте каталог в разделе «Ядро»",
			binDir, free>>20, (tg.Size*4)>>20)
	}

	in.Job.set(func(j *Job) { j.Stage, j.Message = "download", "Скачиваю "+tg.Name })
	tmp, err := os.CreateTemp(binDir, ".dl-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := in.download(ctx, c, tg, tmp); err != nil {
		tmp.Close()
		return "", err
	}
	tmp.Close()

	in.Job.set(func(j *Job) { j.Stage, j.Message, j.Percent = "extract", "Распаковываю…", 90 })
	newBin := filepath.Join(binDir, BinName(core)+".new")
	if err := extract(core, tmp.Name(), newBin); err != nil {
		os.Remove(newBin)
		return "", err
	}
	if err := os.Chmod(newBin, 0o755); err != nil {
		return "", err
	}

	in.Job.set(func(j *Job) { j.Stage, j.Message, j.Percent = "verify", "Проверяю запуск…", 95 })
	ver, err := Version(ctx, core, newBin)
	if err != nil {
		os.Remove(newBin)
		return "", fmt.Errorf("скачанный файл не запускается (возможно, не та архитектура — определено «%s»): %v", in.Info.Arch, err)
	}
	final := filepath.Join(binDir, BinName(core))
	if _, err := os.Stat(final); err == nil {
		_ = os.Rename(final, final+".bak")
	}
	if err := os.Rename(newBin, final); err != nil {
		return "", err
	}
	return ver, nil
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
			pct = float64(p.done) / float64(p.total) * 85
		}
		p.in.Job.set(func(j *Job) {
			j.Percent = pct
			j.Message = fmt.Sprintf("Скачано %.1f МБ", float64(p.done)/(1<<20))
		})
	}
	return len(b), nil
}

func (in *Installer) download(ctx context.Context, c *http.Client, tg target, out *os.File) error {
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
	n, err := io.Copy(out, io.TeeReader(resp.Body, &progressWriter{in: in, total: total}))
	if err != nil {
		return fmt.Errorf("обрыв загрузки: %v", err)
	}
	if total > 0 && n != total {
		return fmt.Errorf("файл скачан не полностью (%d из %d байт)", n, total)
	}
	return nil
}

// extract достаёт бинарник из архива (sing-box: tar.gz, Mihomo: gz).
func extract(core, archive, dst string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("архив повреждён: %v", err)
	}
	defer gz.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()

	if core == model.CoreMihomo {
		_, err = io.Copy(out, gz)
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return errors.New("в архиве нет файла sing-box")
		}
		if err != nil {
			return fmt.Errorf("архив повреждён: %v", err)
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == "sing-box" {
			_, err = io.Copy(out, tr)
			return err
		}
	}
}
