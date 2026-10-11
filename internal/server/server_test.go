package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"corepanel/internal/installer"
	"corepanel/internal/platform"
	"corepanel/internal/store"
	"corepanel/internal/supervisor"
	"corepanel/internal/sysauth"
)

func newTest(t *testing.T) (*httptest.Server, string) { // второй результат оставлен для совместимости вызовов
	t.Helper()
	dir := t.TempDir()
	info := platform.Info{OS: "linux", DataDir: dir, BinDir: dir + "/bin"}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Panel(":0")
	inst := installer.New(info)
	srv := New("test", info, st, supervisor.New(info, inst, st.Get), inst)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, ""
}

func do(t *testing.T, c *http.Client, method, url, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("X-Requested-With", "corepanel")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, e := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if e != nil {
			break
		}
	}
	return resp, sb.String()
}

func TestAuthAndSettings(t *testing.T) {
	ts, _ := newTest(t)
	jar, _ := cookiejarNew()
	c := &http.Client{Jar: jar}

	// по умолчанию вход выключен
	if r, _ := do(t, c, "GET", ts.URL+"/api/settings", ""); r.StatusCode != 200 {
		t.Fatalf("при выключенном входе ожидался 200, получен %d", r.StatusCode)
	}
	// мутации без заголовка запрещены
	req, _ := http.NewRequest("PUT", ts.URL+"/api/settings", strings.NewReader("{}"))
	if r, _ := c.Do(req); r.StatusCode != 403 {
		t.Fatalf("без X-Requested-With ожидался 403, получен %d", r.StatusCode)
	}
	_, body := do(t, c, "GET", ts.URL+"/api/settings", "")
	var set map[string]any
	if err := json.Unmarshal([]byte(body), &set); err != nil {
		t.Fatal(err)
	}
	set["core"] = "mihomo" // будет заменено на amnezia: Mihomo заблокирован
	b, _ := json.Marshal(set)
	if r, out := do(t, c, "PUT", ts.URL+"/api/settings", string(b)); r.StatusCode != 200 {
		t.Fatalf("PUT settings: %d %s", r.StatusCode, out)
	}
	_, body = do(t, c, "GET", ts.URL+"/api/settings", "")
	if !strings.Contains(body, `"core":"amnezia"`) {
		t.Fatalf("настройки не сохранились: %s", body)
	}
	r, out := do(t, c, "POST", ts.URL+"/api/render", body)
	if r.StatusCode != 200 || !strings.Contains(out, "config.json") {
		t.Fatalf("render: %d %s", r.StatusCode, out)
	}
	for _, kind := range []string{"wireguard", "reality", "uuid"} {
		if r, _ := do(t, c, "POST", ts.URL+"/api/keygen", `{"kind":"`+kind+`"}`); r.StatusCode != 200 {
			t.Fatalf("keygen %s: %d", kind, r.StatusCode)
		}
	}
	if r, _ := do(t, c, "GET", ts.URL+"/api/clash/proxies", ""); r.StatusCode != 502 {
		t.Fatalf("clash без ядра: %d", r.StatusCode)
	}
}

func TestStatic(t *testing.T) {
	ts, _ := newTest(t)
	resp, err := http.Get(ts.URL + "/")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("index: %v %v", err, resp)
	}
}

// Сессия должна переживать перезапуск панели (новый Server с тем же каталогом данных).
func TestSessionSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	info := platform.Info{OS: "linux", DataDir: dir, BinDir: dir + "/bin"}
	shadowWithTest(t)
	mk := func() (*httptest.Server, string) {
		st, _ := store.Open(dir)
		st.Panel(":0")
		inst := installer.New(info)
		ts := httptest.NewServer(New("t", info, st, supervisor.New(info, inst, st.Get), inst).Handler())
		t.Cleanup(ts.Close)
		return ts, ""
	}
	ts1, _ := mk()
	jar, _ := cookiejarNew()
	c := &http.Client{Jar: jar}
	if r, _ := do(t, c, "POST", ts1.URL+"/api/auth", `{"enabled":true,"password":"test"}`); r.StatusCode != 200 {
		t.Fatal("включение входа")
	}
	cookies := jar.Cookies(mustURL(ts1.URL))
	ts2, _ := mk() // «перезапуск»
	jar2, _ := cookiejarNew()
	jar2.SetCookies(mustURL(ts2.URL), cookies)
	if r, _ := do(t, &http.Client{Jar: jar2}, "GET", ts2.URL+"/api/settings", ""); r.StatusCode != 200 {
		t.Fatalf("после перезапуска сессия потеряна: %d", r.StatusCode)
	}
}

func TestCoreInstallBlocked(t *testing.T) {
	ts, _ := newTest(t)
	jar, _ := cookiejarNew()
	c := &http.Client{Jar: jar}
	if r, _ := do(t, c, "POST", ts.URL+"/api/core/install", `{"core":"mihomo"}`); r.StatusCode != 403 {
		t.Fatalf("установка Mihomo должна быть заблокирована: %d", r.StatusCode)
	}
	if r, _ := do(t, c, "POST", ts.URL+"/api/core/install", `{"core":"singbox"}`); r.StatusCode != 400 {
		t.Fatalf("sing-box убран из проекта: %d", r.StatusCode)
	}
}

// shadowWithTest подменяет shadow: пароль root — «test» (md5-crypt).
func shadowWithTest(t *testing.T) {
	t.Helper()
	f := t.TempDir() + "/shadow"
	if err := os.WriteFile(f, []byte("root:$1$abcdefgh$irWbblnpmw.5z7wgBnprh0:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := sysauth.ShadowFiles
	sysauth.ShadowFiles = []string{f}
	t.Cleanup(func() { sysauth.ShadowFiles = old })
}

func TestRootPasswordAuth(t *testing.T) {
	shadowWithTest(t)
	ts, _ := newTest(t)
	jar, _ := cookiejarNew()
	c := &http.Client{Jar: jar}
	if r, _ := do(t, c, "POST", ts.URL+"/api/auth", `{"enabled":true,"password":"bad"}`); r.StatusCode != 400 {
		t.Fatalf("включение с неверным паролем должно отказывать: %d", r.StatusCode)
	}
	if r, _ := do(t, c, "GET", ts.URL+"/api/settings", ""); r.StatusCode != 200 {
		t.Fatal("после неудачного включения вход должен остаться выключенным")
	}
	if r, _ := do(t, c, "POST", ts.URL+"/api/auth", `{"enabled":true,"password":"test"}`); r.StatusCode != 200 {
		t.Fatalf("включение: %d", r.StatusCode)
	}
	if r, _ := do(t, c, "GET", ts.URL+"/api/settings", ""); r.StatusCode != 200 {
		t.Fatal("текущий браузер должен остаться в системе")
	}
	other := &http.Client{}
	if r, _ := do(t, other, "GET", ts.URL+"/api/settings", ""); r.StatusCode != 401 {
		t.Fatalf("без входа ожидался 401: %d", r.StatusCode)
	}
	if r, _ := do(t, other, "POST", ts.URL+"/api/login", `{"username":"root","password":"bad"}`); r.StatusCode != 401 {
		t.Fatalf("неверный пароль: %d", r.StatusCode)
	}
	jar2, _ := cookiejarNew()
	c2 := &http.Client{Jar: jar2}
	if r, _ := do(t, c2, "POST", ts.URL+"/api/login", `{"username":"root","password":"test"}`); r.StatusCode != 200 {
		t.Fatalf("вход по паролю root: %d", r.StatusCode)
	}
	if r, _ := do(t, c2, "GET", ts.URL+"/api/settings", ""); r.StatusCode != 200 {
		t.Fatal("после входа настройки должны открываться")
	}
	if r, _ := do(t, c2, "POST", ts.URL+"/api/auth", `{"enabled":false}`); r.StatusCode != 200 {
		t.Fatal("выключение")
	}
	if r, _ := do(t, other, "GET", ts.URL+"/api/settings", ""); r.StatusCode != 200 {
		t.Fatal("после выключения вход не нужен")
	}
}

func TestLocalOnlyWhenOpen(t *testing.T) {
	for ip, want := range map[string]bool{"192.168.1.5": true, "10.0.0.1": true, "127.0.0.1": true, "fe80::1": true, "fd00::1": true, "8.8.8.8": false, "2001:db8::1": false} {
		if isLocalAddr(ip) != want {
			t.Errorf("%s: ожидалось %v", ip, want)
		}
	}
}
