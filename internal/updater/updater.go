// Package updater — проверка и установка новых версий самой панели с GitHub Releases
// (https://github.com/phenomenonRT/panel_awg-box_sing-box/releases). Берётся готовый бинарник
// corepanel-linux-<arch>, проверяется по SHA256SUMS.txt и подменяет текущий файл; затем
// панель перезапускает сама себя (exec); работающее ядро не трогается и подхватывается новым процессом.
package updater

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"corepanel/internal/model"
	"corepanel/internal/platform"
)

// latestURL — последний релиз (переопределяется в тестах).
var latestURL = "https://api.github.com/repos/phenomenonRT/panel_awg-box_sing-box/releases/latest"

// ResumeMarker — файл в каталоге данных: запасной путь, когда передать работающее ядро не удалось
// и оно было остановлено — после обновления его нужно запустить снова.
const ResumeMarker = "resume-core"

// Info — результат проверки.
type Info struct {
	Current   string `json:"current"`
	Latest    string `json:"latest,omitempty"`
	Available bool   `json:"available"`
	PageURL   string `json:"page_url,omitempty"`
	CheckedAt int64  `json:"checked_at,omitempty"`
	CanApply  bool   `json:"can_apply"`
	Reason    string `json:"reason,omitempty"` // почему обновить нельзя / проверка не удалась
}

// Job — состояние установки.
type Job struct {
	Running  bool     `json:"running"`
	Finished bool     `json:"finished"`
	Error    string   `json:"error,omitempty"`
	Output   []string `json:"output"`
}

// State — то, что видит интерфейс.
type State struct {
	Info
	Job Job `json:"job"`
}

type Updater struct {
	Version  string
	Info     platform.Info
	Settings func() *model.Settings
	// Restart перезапускает процесс панели (ядро передаётся новому процессу); при успехе не возвращается.
	Restart func() error
	// ExePath — путь к исполняемому файлу панели (в тестах подменяется).
	ExePath func() (string, error)

	mu          sync.Mutex
	last        Info
	job         Job
	asset, sums string
}

func New(version string, info platform.Info, settings func() *model.Settings, restart func() error) *Updater {
	return &Updater{Version: version, Info: info, Settings: settings, Restart: restart, ExePath: os.Executable}
}

// parseVersion разбирает «v0.1.24» → [0 1 24].
func parseVersion(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return nil, false
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// Newer сообщает, что latest новее current. При непонятной версии — false.
func Newer(latest, current string) bool {
	a, ok1 := parseVersion(latest)
	b, ok2 := parseVersion(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func (u *Updater) client() (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if d := u.Settings().Download; d.Proxy != "" {
		pu, err := url.Parse(d.Proxy)
		if err != nil {
			return nil, fmt.Errorf("неверный адрес прокси «%s»", d.Proxy)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Minute}, nil
}

func (u *Updater) withMirror(s string) string {
	if m := strings.TrimSpace(u.Settings().Download.Mirror); m != "" {
		return strings.TrimRight(m, "/") + "/" + s
	}
	return s
}

// State возвращает последнее известное состояние без обращения к сети.
func (u *Updater) State() State {
	u.mu.Lock()
	defer u.mu.Unlock()
	i := u.last
	i.Current = u.Version
	return State{Info: i, Job: Job{Running: u.job.Running, Finished: u.job.Finished, Error: u.job.Error, Output: append([]string{}, u.job.Output...)}}
}

// Check запрашивает последний релиз.
func (u *Updater) Check(ctx context.Context) Info {
	info := Info{Current: u.Version, CheckedAt: time.Now().Unix()}
	fail := func(f string, a ...any) Info {
		info.Reason = fmt.Sprintf(f, a...)
		u.mu.Lock()
		u.last = info
		u.mu.Unlock()
		return info
	}
	cl, err := u.client()
	if err != nil {
		return fail("%v", err)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", latestURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := cl.Do(req)
	if err != nil {
		return fail("GitHub недоступен: %v. Укажите зеркало или прокси в «Компонентах»", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fail("GitHub вернул HTTP %d", resp.StatusCode)
	}
	var rel struct {
		Tag    string `json:"tag_name"`
		URL    string `json:"html_url"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return fail("не удалось разобрать ответ GitHub")
	}
	info.Latest = strings.TrimPrefix(rel.Tag, "v")
	info.PageURL = rel.URL
	info.Available = Newer(rel.Tag, u.Version)
	var asset, sums string
	want := "corepanel-linux-" + u.Info.Arch
	for _, a := range rel.Assets {
		switch a.Name {
		case want:
			asset = a.URL
		case "SHA256SUMS.txt":
			sums = a.URL
		}
	}
	switch {
	case asset == "" || sums == "":
		if info.Available {
			info.Reason = "в релизе нет файла " + want + " или SHA256SUMS.txt"
		}
	case u.Info.OS == "" || u.Info.Arch == "":
		info.Reason = "не удалось определить платформу"
	default:
		info.CanApply = true
	}
	if _, ok := parseVersion(u.Version); !ok && info.Reason == "" {
		info.Reason = "версия этой сборки (" + u.Version + ") не числовая — сравнить нельзя"
	}
	u.mu.Lock()
	u.last, u.asset, u.sums = info, asset, sums
	u.mu.Unlock()
	return info
}

func (u *Updater) add(l string) {
	u.mu.Lock()
	u.job.Output = append(u.job.Output, l)
	u.mu.Unlock()
}

func (u *Updater) finish(err error) {
	u.mu.Lock()
	u.job.Running, u.job.Finished = false, true
	if err != nil {
		u.job.Error = err.Error()
	}
	u.mu.Unlock()
}

// Apply скачивает и ставит последнюю проверенную версию (асинхронно).
func (u *Updater) Apply() error {
	u.mu.Lock()
	if u.job.Running {
		u.mu.Unlock()
		return errors.New("обновление уже идёт")
	}
	if !u.last.Available || !u.last.CanApply || u.asset == "" {
		u.mu.Unlock()
		return errors.New("нет доступного обновления: сначала нажмите «Проверить»")
	}
	asset, sums, ver := u.asset, u.sums, u.last.Latest
	u.job = Job{Running: true}
	u.mu.Unlock()
	go func() { u.finish(u.run(asset, sums, ver)) }()
	return nil
}

func parseSums(body, name string) string {
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

func (u *Updater) run(assetURL, sumsURL, ver string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cl, err := u.client()
	if err != nil {
		return err
	}
	exe, err := u.ExePath()
	if err != nil {
		return fmt.Errorf("не удалось определить путь панели: %v", err)
	}
	if r, e := filepath.EvalSymlinks(exe); e == nil {
		exe = r
	}
	get := func(link string) (*http.Response, error) {
		req, _ := http.NewRequestWithContext(ctx, "GET", u.withMirror(link), nil)
		resp, err := cl.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return resp, nil
	}
	u.add("версия " + ver + ": проверяю контрольную сумму")
	resp, err := get(sumsURL)
	if err != nil {
		return fmt.Errorf("SHA256SUMS.txt: %v", err)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	want := parseSums(string(b), "corepanel-linux-"+u.Info.Arch)
	if want == "" {
		return errors.New("в SHA256SUMS.txt нет суммы для " + u.Info.Arch)
	}

	tmp := exe + ".new"
	u.add("скачиваю corepanel-linux-" + u.Info.Arch)
	resp, err = get(assetURL)
	if err != nil {
		return fmt.Errorf("загрузка: %v", err)
	}
	defer resp.Body.Close()
	if resp.ContentLength > 0 {
		if free := platform.FreeMB(filepath.Dir(exe)); free > 0 && int64(free) < resp.ContentLength>>20+1 {
			return fmt.Errorf("не хватает места рядом с панелью: свободно %d МБ, нужно около %d МБ", free, resp.ContentLength>>20+1)
		}
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("нельзя записать %s: %v", tmp, err)
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("обрыв загрузки или не хватает места: %v", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(tmp)
		return errors.New("контрольная сумма не совпала — файл повреждён, обновление отменено")
	}
	u.add("контрольная сумма верна, проверяю запуск")
	out, err := exec.CommandContext(ctx, tmp, "version").Output()
	if err != nil || strings.TrimPrefix(strings.TrimSpace(string(out)), "v") != ver {
		os.Remove(tmp)
		return fmt.Errorf("новая версия не запускается или сообщила другую версию (%q)", strings.TrimSpace(string(out)))
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("не удалось заменить %s: %v", exe, err)
	}
	u.add("файл заменён, перезапускаю панель")
	time.Sleep(1500 * time.Millisecond) // дать интерфейсу прочитать состояние
	if u.Restart == nil {
		return nil
	}
	if err := u.Restart(); err != nil {
		return fmt.Errorf("файл заменён, но перезапуск не удался (%v): перезапустите панель вручную", err)
	}
	return nil
}

// AutoLoop раз в несколько часов проверяет релизы и, если включено автообновление, ставит новую версию.
func (u *Updater) AutoLoop(ctx context.Context) {
	t := time.NewTimer(3 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if u.Settings().Update.Auto {
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			info := u.Check(cctx)
			cancel()
			if info.Available && info.CanApply {
				_ = u.Apply()
			}
		}
		t.Reset(6 * time.Hour)
	}
}
