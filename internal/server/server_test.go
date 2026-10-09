package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"corepanel/internal/installer"
	"corepanel/internal/platform"
	"corepanel/internal/store"
	"corepanel/internal/supervisor"
)

func newTest(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	info := platform.Info{OS: "linux", DataDir: dir, BinDir: dir + "/bin"}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, pw, _ := st.Panel(":0")
	inst := installer.New(info)
	srv := New("test", info, st, supervisor.New(info, inst, st.Get), inst)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, pw
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
	ts, pw := newTest(t)
	jar, _ := cookiejarNew()
	c := &http.Client{Jar: jar}

	if r, _ := do(t, c, "GET", ts.URL+"/api/settings", ""); r.StatusCode != 401 {
		t.Fatalf("без входа ожидался 401, получен %d", r.StatusCode)
	}
	if r, _ := do(t, c, "POST", ts.URL+"/api/login", `{"username":"admin","password":"bad"}`); r.StatusCode != 401 {
		t.Fatalf("неверный пароль: %d", r.StatusCode)
	}
	if r, _ := do(t, c, "POST", ts.URL+"/api/login", `{"username":"admin","password":"`+pw+`"}`); r.StatusCode != 200 {
		t.Fatalf("вход: %d", r.StatusCode)
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
	set["core"] = "mihomo"
	b, _ := json.Marshal(set)
	if r, out := do(t, c, "PUT", ts.URL+"/api/settings", string(b)); r.StatusCode != 200 {
		t.Fatalf("PUT settings: %d %s", r.StatusCode, out)
	}
	_, body = do(t, c, "GET", ts.URL+"/api/settings", "")
	if !strings.Contains(body, `"core":"mihomo"`) {
		t.Fatalf("настройки не сохранились: %s", body)
	}
	r, out := do(t, c, "POST", ts.URL+"/api/render", body)
	if r.StatusCode != 200 || !strings.Contains(out, "config.yaml") {
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
	mk := func() (*httptest.Server, string) {
		st, _ := store.Open(dir)
		_, pw, _ := st.Panel(":0")
		inst := installer.New(info)
		ts := httptest.NewServer(New("t", info, st, supervisor.New(info, inst, st.Get), inst).Handler())
		t.Cleanup(ts.Close)
		return ts, pw
	}
	ts1, pw := mk()
	jar, _ := cookiejarNew()
	c := &http.Client{Jar: jar}
	if r, _ := do(t, c, "POST", ts1.URL+"/api/login", `{"username":"admin","password":"`+pw+`"}`); r.StatusCode != 200 {
		t.Fatal("вход")
	}
	cookies := jar.Cookies(mustURL(ts1.URL))
	ts2, _ := mk() // «перезапуск»
	jar2, _ := cookiejarNew()
	jar2.SetCookies(mustURL(ts2.URL), cookies)
	if r, _ := do(t, &http.Client{Jar: jar2}, "GET", ts2.URL+"/api/settings", ""); r.StatusCode != 200 {
		t.Fatalf("после перезапуска сессия потеряна: %d", r.StatusCode)
	}
}

func TestPodkopStatusAndGuard(t *testing.T) {
	ts, pw := newTest(t)
	jar, _ := cookiejarNew()
	c := &http.Client{Jar: jar}
	do(t, c, "POST", ts.URL+"/api/login", `{"username":"admin","password":"`+pw+`"}`)
	r, out := do(t, c, "GET", ts.URL+"/api/podkop", "")
	if r.StatusCode != 200 || !strings.Contains(out, `"supported":false`) {
		t.Fatalf("не-OpenWrt должен возвращать supported=false: %d %s", r.StatusCode, out)
	}
	if r, _ := do(t, c, "POST", ts.URL+"/api/podkop/install", "{}"); r.StatusCode != 400 {
		t.Fatalf("установка вне OpenWrt должна отказывать: %d", r.StatusCode)
	}
	if r, _ := do(t, c, "POST", ts.URL+"/api/podkop/bogus", "{}"); r.StatusCode != 400 {
		t.Fatalf("неизвестное действие: %d", r.StatusCode)
	}
}
