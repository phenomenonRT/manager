// Package server — HTTP API и раздача веб-интерфейса.
package server

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"corepanel/internal/firewall"
	"corepanel/internal/importer"
	"corepanel/internal/installer"
	"corepanel/internal/model"
	"corepanel/internal/platform"
	"corepanel/internal/podkop"
	"corepanel/internal/store"
	"corepanel/internal/supervisor"
	"corepanel/internal/sysauth"
	"corepanel/web"
)

const cookieName = "cp_session"

type Server struct {
	Version string
	Info    platform.Info
	St      *store.Store
	Sup     *supervisor.Supervisor
	Inst    *installer.Installer
	Podkop  *podkop.Manager

	mu    sync.Mutex
	key   []byte // ключ подписи сессий (хранится на диске — вход переживает перезапуск панели)
	fails map[string]*failure
}

type failure struct {
	n     int
	until time.Time
}

func New(version string, info platform.Info, st *store.Store, sup *supervisor.Supervisor, inst *installer.Installer) *Server {
	return &Server{Version: version, Info: info, St: st, Sup: sup, Inst: inst, Podkop: podkop.New(info),
		key: loadKey(st.Dir()), fails: map[string]*failure{}}
}

func loadKey(dir string) []byte {
	path := filepath.Join(dir, "session.key")
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	_ = os.WriteFile(path, b, 0o600)
	return b
}

const sessionTTL = 30 * 24 * time.Hour

// makeToken подписывает срок действия; подпись привязана к хешу пароля,
// поэтому смена пароля завершает все сессии.
func (s *Server) makeToken() string {
	exp := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)
	return exp + "." + s.sign(exp)
}

func (s *Server) sign(exp string) string {
	m := hmac.New(sha256.New, append(append([]byte{}, s.key...), s.St.PanelInfo().Epoch...))
	m.Write([]byte(exp))
	return fmt.Sprintf("%x", m.Sum(nil))
}

func (s *Server) validToken(tok string) bool {
	exp, sig, found := strings.Cut(tok, ".")
	if !found || !hmac.Equal([]byte(sig), []byte(s.sign(exp))) {
		return false
	}
	e, err := strconv.ParseInt(exp, 10, 64)
	if err != nil {
		return false
	}
	// На роутерах без RTC время до синхронизации NTP неверно — срок не проверяем.
	if time.Now().Year() < 2024 {
		return true
	}
	return time.Now().Unix() < e
}

// Handler собирает маршруты.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	api := func(method, path string, h http.HandlerFunc, auth bool) {
		mux.HandleFunc(method+" /api/"+path, func(w http.ResponseWriter, r *http.Request) {
			if method != "GET" && r.Header.Get("X-Requested-With") != "corepanel" {
				fail(w, 403, "нет заголовка X-Requested-With")
				return
			}
			if auth && !s.authed(r) {
				fail(w, 401, "требуется вход")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
			h(w, r)
		})
	}
	api("GET", "session", s.session, false)
	api("POST", "login", s.login, false)
	api("POST", "logout", s.logout, false)
	api("POST", "auth", s.setAuth, true)
	api("POST", "panel", s.panel, true)
	api("GET", "system", s.system, true)
	api("GET", "settings", func(w http.ResponseWriter, r *http.Request) { ok(w, s.St.Get()) }, true)
	api("PUT", "settings", s.putSettings, true)
	api("POST", "validate", s.validate, true)
	api("POST", "render", s.render, true)
	api("GET", "status", func(w http.ResponseWriter, r *http.Request) { ok(w, s.Sup.Status()) }, true)
	api("POST", "service/start", s.svc("start"), true)
	api("POST", "service/stop", s.svc("stop"), true)
	api("POST", "service/restart", s.svc("restart"), true)
	api("POST", "core/install", s.coreInstall, true)
	api("POST", "core/remove", s.coreRemove, true)
	api("GET", "core/job", func(w http.ResponseWriter, r *http.Request) { ok(w, s.Inst.Job.Snapshot()) }, true)
	api("POST", "import", s.importText, true)
	api("POST", "import/url", s.importURL, true)
	api("POST", "keygen", s.keygen, true)
	api("GET", "interfaces", s.interfaces, true)
	api("GET", "firewall/preview", s.fwPreview, true)
	api("GET", "logs", s.logs, true)
	api("GET", "logs/stream", s.logStream, true)
	api("GET", "podkop", func(w http.ResponseWriter, r *http.Request) { ok(w, s.Podkop.Status(r.Context())) }, true)
	api("POST", "podkop/{action}", s.podkopAction, true)

	// Прокси к Clash API ядра (любой метод, поэтому вне api()).
	mux.HandleFunc("/api/clash/", func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			fail(w, 401, "требуется вход")
			return
		}
		if r.Method != "GET" && r.Header.Get("X-Requested-With") != "corepanel" {
			fail(w, 403, "нет заголовка X-Requested-With")
			return
		}
		s.clash(w, r)
	})

	files := http.FileServer(http.FS(web.FS()))
	mux.Handle("/", noCache(files))
	return secure(s.localOnly(mux))
}

func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		if o := r.Header.Get("Origin"); o != "" && r.Method != "GET" {
			if u, err := url.Parse(o); err != nil || u.Host != r.Host {
				fail(w, 403, "чужой Origin")
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// ---------- ответы ----------

func ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		fail(w, 400, "неверный JSON: "+err.Error())
		return false
	}
	return true
}

// ---------- сессии ----------

func (s *Server) authed(r *http.Request) bool {
	if !s.St.PanelInfo().AuthEnabled {
		return true // вход выключен (доступ ограничен локальной сетью, см. localOnly)
	}
	c, err := r.Cookie(cookieName)
	return err == nil && s.validToken(c.Value)
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	p := s.St.PanelInfo()
	ok(w, map[string]any{"authenticated": s.authed(r), "auth_enabled": p.AuthEnabled, "user": "root"})
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if !decode(w, r, &in) {
		return
	}
	ip := clientIP(r)
	s.mu.Lock()
	f := s.fails[ip]
	if f != nil && time.Now().Before(f.until) {
		s.mu.Unlock()
		fail(w, 429, "слишком много попыток, подождите немного")
		return
	}
	s.mu.Unlock()
	good, verr := false, error(nil)
	if in.Username == "" || in.Username == "root" {
		good, verr = sysauth.Verify("root", in.Password)
	}
	if verr != nil && !good {
		fail(w, 400, "Не удаётся проверить пароль root: "+verr.Error())
		return
	}
	if !good {
		s.mu.Lock()
		if f == nil {
			f = &failure{}
			s.fails[ip] = f
		}
		f.n++
		if f.n >= 5 {
			f.until = time.Now().Add(time.Duration(f.n) * 10 * time.Second)
		}
		s.mu.Unlock()
		time.Sleep(500 * time.Millisecond)
		fail(w, 401, "неверный пароль root")
		return
	}
	s.mu.Lock()
	delete(s.fails, ip)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.makeToken(), Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	p := s.St.PanelInfo()
	ok(w, map[string]any{"authenticated": true, "auth_enabled": p.AuthEnabled, "user": "root"})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	ok(w, map[string]bool{"ok": true})
}

// setAuth включает или выключает вход. Включить можно, только подтвердив пароль root:
// так нельзя случайно запереть себя с паролем, которого не существует.
func (s *Server) setAuth(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled  bool
		Password string
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Enabled {
		okp, err := sysauth.Verify("root", in.Password)
		if err != nil && !okp {
			fail(w, 400, "Вход не включён: "+err.Error())
			return
		}
		if !okp {
			fail(w, 400, "неверный пароль root")
			return
		}
	}
	if err := s.St.SetAuth(in.Enabled); err != nil {
		fail(w, 500, err.Error())
		return
	}
	if in.Enabled { // текущему браузеру выдаём новую сессию
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.makeToken(), Path: "/", HttpOnly: true,
			SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	}
	ok(w, map[string]any{"auth_enabled": in.Enabled})
}

// localOnly: пока вход выключен, панель отвечает только устройствам локальной сети
// (иначе открытая на WAN панель была бы доступна всему интернету без пароля).
func (s *Server) localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.St.PanelInfo().AuthEnabled && !isLocalAddr(clientIP(r)) {
			fail(w, 403, "вход в панель выключен, поэтому она доступна только из локальной сети; включите вход по паролю root в разделе «Система»")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLocalAddr(ip string) bool {
	a, err := netip.ParseAddr(strings.Split(ip, "%")[0])
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast()
}

func (s *Server) panel(w http.ResponseWriter, r *http.Request) {
	var in struct{ Listen string }
	if !decode(w, r, &in) {
		return
	}
	if _, port, err := net.SplitHostPort(in.Listen); err != nil {
		fail(w, 400, "адрес в формате host:port, например 0.0.0.0:8088 или :8088")
		return
	} else if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		fail(w, 400, "неверный порт")
		return
	}
	if err := s.St.SetListen(in.Listen); err != nil {
		fail(w, 500, err.Error())
		return
	}
	ok(w, map[string]any{"ok": true, "restart_required": true})
}

// ---------- система ----------

type coreInfo struct {
	Installed bool   `json:"installed"`
	Path      string `json:"path"`
	Version   string `json:"version"`
}

func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	set := s.St.Get()
	cores := map[string]coreInfo{}
	for _, c := range []string{model.CoreSingbox, model.CoreMihomo, model.CoreAmnezia} {
		ci := coreInfo{}
		if p := s.Inst.Locate(c, set.Download); p != "" {
			ci.Installed, ci.Path = true, p
			if v, err := installer.Version(r.Context(), c, p); err == nil {
				ci.Version = v
			}
		}
		cores[c] = ci
	}
	binDir := s.Inst.BinDir(set.Download)
	installed := map[string]int{}
	for _, c := range []string{model.CoreSingbox, model.CoreMihomo, model.CoreAmnezia} {
		installed[c] = s.Inst.InstalledMB(c, set.Download)
	}
	ok(w, map[string]any{"panel_version": s.Version, "platform": s.Info, "cores": cores,
		"listen":  s.St.PanelInfo().Listen,
		"storage": map[string]any{"dir": binDir, "free_mb": platform.FreeMB(binDir), "need_mb": installer.NeedMB, "installed_mb": installed}})
}

func (s *Server) interfaces(w http.ResponseWriter, r *http.Request) {
	type ifc struct {
		Name  string   `json:"name"`
		Up    bool     `json:"up"`
		Addrs []string `json:"addrs"`
	}
	out := []ifc{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		x := ifc{Name: i.Name, Up: i.Flags&net.FlagUp != 0, Addrs: []string{}}
		if as, err := i.Addrs(); err == nil {
			for _, a := range as {
				x.Addrs = append(x.Addrs, a.String())
			}
		}
		out = append(out, x)
	}
	ok(w, out)
}

// ---------- настройки ----------

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	set := model.Default()
	if !decode(w, r, set) {
		return
	}
	set.Normalize()
	if err := s.St.Set(set); err != nil {
		fail(w, 500, err.Error())
		return
	}
	ok(w, map[string]any{"ok": true, "issues": nonNil(set.Validate())})
}

func nonNil(i []model.Issue) []model.Issue {
	if i == nil {
		return []model.Issue{}
	}
	return i
}

func (s *Server) readSettings(w http.ResponseWriter, r *http.Request) *model.Settings {
	set := model.Default()
	if !decode(w, r, set) {
		return nil
	}
	set.Normalize()
	return set
}

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	if set := s.readSettings(w, r); set != nil {
		ok(w, map[string]any{"issues": nonNil(set.Validate())})
	}
}

func (s *Server) render(w http.ResponseWriter, r *http.Request) {
	set := s.readSettings(w, r)
	if set == nil {
		return
	}
	res, err := supervisor.Render(set)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	ok(w, res)
}

func (s *Server) fwPreview(w http.ResponseWriter, r *http.Request) {
	set := s.St.Get()
	sp, err := firewall.FromSettings(set, s.Info.FirewallBE)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if sp == nil {
		ok(w, map[string]string{"up": "", "down": ""})
		return
	}
	sc, err := firewall.Generate(sp)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	ok(w, sc)
}

// ---------- сервис и ядро ----------

func (s *Server) svc(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		set := s.St.Get()
		var err error
		if (action == "start" || action == "restart") && podkop.IsRunning(r.Context()) {
			fail(w, 409, "Работает Podkop: он тоже управляет sing-box, DNS и правилами nft, одновременно с ядром панели их запускать нельзя. Остановите Podkop на странице «Podkop».")
			return
		}
		switch action {
		case "start":
			err = s.Sup.Start(set)
		case "stop":
			err = s.Sup.Stop()
		case "restart":
			err = s.Sup.Restart(set)
		}
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		ok(w, s.Sup.Status())
	}
}

func (s *Server) coreInstall(w http.ResponseWriter, r *http.Request) {
	var in struct{ Core, Version, Source string }
	if !decode(w, r, &in) {
		return
	}
	if in.Core != model.CoreSingbox && in.Core != model.CoreMihomo && in.Core != model.CoreAmnezia {
		fail(w, 400, "core: singbox, mihomo или amnezia")
		return
	}
	var err error
	if in.Source != "package" {
		dl := s.St.Get().Download
		dir := s.Inst.BinDir(dl)
		if free := platform.FreeMB(dir); free > 0 && free+s.Inst.InstalledMB(in.Core, dl) < installer.NeedMB[in.Core] {
			fail(w, 400, fmt.Sprintf("Не хватает места в %s: свободно %d МБ, нужно около %d МБ. Подключите накопитель и укажите каталог установки либо установите из пакетов системы.",
				dir, free, installer.NeedMB[in.Core]))
			return
		}
	}
	if in.Source == "package" {
		err = s.Inst.StartPackage(in.Core)
	} else {
		err = s.Inst.Start(in.Core, strings.TrimSpace(in.Version), s.St.Get().Download)
	}
	if err != nil {
		fail(w, 409, err.Error())
		return
	}
	ok(w, s.Inst.Job.Snapshot())
}

func (s *Server) coreRemove(w http.ResponseWriter, r *http.Request) {
	var in struct{ Core string }
	if !decode(w, r, &in) {
		return
	}
	if st := s.Sup.Status(); (st.State == "running" || st.State == "starting") && st.Core == in.Core {
		fail(w, 409, "Ядро сейчас работает — сначала остановите его.")
		return
	}
	what, err := s.Inst.Remove(r.Context(), in.Core, s.St.Get().Download)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	ok(w, map[string]string{"removed": what})
}

// ---------- импорт и ключи ----------

func (s *Server) importText(w http.ResponseWriter, r *http.Request) {
	var in struct{ Text string }
	if !decode(w, r, &in) {
		return
	}
	ok(w, normImport(importer.Parse(in.Text)))
}

func normImport(r importer.Result) importer.Result {
	if r.Nodes == nil {
		r.Nodes = []model.Node{}
	}
	if r.Errors == nil {
		r.Errors = []string{}
	}
	return r
}

func (s *Server) importURL(w http.ResponseWriter, r *http.Request) {
	var in struct{ URL string }
	if !decode(w, r, &in) {
		return
	}
	u, err := url.Parse(strings.TrimSpace(in.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fail(w, 400, "нужен http(s)-адрес подписки")
		return
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if p := s.St.Get().Download.Proxy; p != "" {
		if pu, err := url.Parse(p); err == nil && pu.Host != "" {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	req.Header.Set("User-Agent", "clash.meta corepanel")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		fail(w, 502, "не удалось скачать подписку: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fail(w, 502, fmt.Sprintf("сервер подписки ответил %d", resp.StatusCode))
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	ok(w, normImport(importer.Parse(string(body))))
}

func (s *Server) keygen(w http.ResponseWriter, r *http.Request) {
	var in struct{ Kind string }
	if !decode(w, r, &in) {
		return
	}
	switch in.Kind {
	case "wireguard", "reality":
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		enc := base64.StdEncoding
		if in.Kind == "reality" {
			enc = base64.RawURLEncoding
		}
		ok(w, map[string]string{"private": enc.EncodeToString(k.Bytes()), "public": enc.EncodeToString(k.PublicKey().Bytes())})
	case "uuid":
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		b[6] = b[6]&0x0f | 0x40
		b[8] = b[8]&0x3f | 0x80
		ok(w, map[string]string{"uuid": fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])})
	default:
		fail(w, 400, "kind: wireguard, reality или uuid")
	}
}

// ---------- логи ----------

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 {
		n = 300
	}
	ok(w, map[string]any{"lines": s.Sup.Logs.Tail(n)})
}

func (s *Server) logStream(w http.ResponseWriter, r *http.Request) {
	fl, okf := w.(http.Flusher)
	if !okf {
		fail(w, 500, "потоковая передача недоступна")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	ch, cancel := s.Sup.Logs.Subscribe()
	defer cancel()
	fmt.Fprint(w, ": ok\n\n")
	fl.Flush()
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case line := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", strings.ReplaceAll(line, "\n", " "))
			fl.Flush()
		case <-tick.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

// ---------- Clash API ----------

func (s *Server) clash(w http.ResponseWriter, r *http.Request) {
	set := s.St.Get()
	host, port, err := net.SplitHostPort(set.General.Controller)
	if err != nil {
		fail(w, 502, "неверный адрес controller")
		return
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	target := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, port)}
	secret := set.General.Secret
	rp := &httputil.ReverseProxy{
		FlushInterval: -1,
		Director: func(req *http.Request) {
			req.URL.Scheme, req.URL.Host = target.Scheme, target.Host
			req.URL.Path = strings.TrimPrefix(req.URL.Path, "/api/clash")
			req.URL.RawPath = ""
			req.Host = target.Host
			req.Header.Del("Cookie")
			req.Header.Del("Origin")
			req.Header.Del("X-Requested-With")
			if secret != "" {
				req.Header.Set("Authorization", "Bearer "+secret)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode == http.StatusUnauthorized {
				resp.StatusCode = http.StatusBadGateway
				resp.Status = "502 Bad Gateway"
				body := `{"error":"ядро отклонило запрос (проверьте secret в настройках или не занят ли порт controller другой программой)"}`
				resp.Body = io.NopCloser(strings.NewReader(body))
				resp.ContentLength = int64(len(body))
				resp.Header.Set("Content-Type", "application/json; charset=utf-8")
				resp.Header.Del("Content-Length")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			fail(w, 502, "ядро не отвечает (запущено ли оно?)")
		},
	}
	rp.ServeHTTP(w, r)
}

// ---------- Podkop ----------

func (s *Server) podkopAction(w http.ResponseWriter, r *http.Request) {
	var err error
	switch a := r.PathValue("action"); a {
	case "install":
		err = s.Podkop.Install(false)
	case "install-mirror":
		err = s.Podkop.Install(true)
	case "remove":
		err = s.Podkop.Remove()
	case "start", "restart":
		// Podkop и ядро панели перехватывают DNS и трафик — вместе не запускаем.
		if st := s.Sup.Status(); st.State == "running" {
			fail(w, 409, "Сейчас работает ядро панели. Остановите его на странице «Обзор», затем запускайте Podkop.")
			return
		}
		_, err = s.Podkop.Control(r.Context(), a)
	default:
		_, err = s.Podkop.Control(r.Context(), a)
	}
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	ok(w, s.Podkop.Status(r.Context()))
}
