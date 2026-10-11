package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"corepanel/internal/model"
	"corepanel/internal/platform"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v0.1.25", "0.1.24", true}, {"0.1.24", "0.1.24", false}, {"0.1.9", "0.1.10", false},
		{"0.2.0", "0.1.99", true}, {"1.0", "0.9.9", true}, {"0.1.25", "dev", false}, {"x", "0.1.0", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q,%q)=%v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestParseSums(t *testing.T) {
	body := "AABB  corepanel-linux-amd64\nccdd *corepanel-linux-arm64\n"
	if parseSums(body, "corepanel-linux-amd64") != "aabb" || parseSums(body, "corepanel-linux-arm64") != "ccdd" || parseSums(body, "x") != "" {
		t.Fatal("разбор SHA256SUMS")
	}
}

func fakeRelease(t *testing.T, tag, script string, badSum bool) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256([]byte(script))
	hexsum := hex.EncodeToString(sum[:])
	if badSum {
		hexsum = strings.Repeat("0", 64)
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			fmt.Fprintf(w, `{"tag_name":%q,"html_url":"https://example.test/r","assets":[{"name":"corepanel-linux-amd64","browser_download_url":%q},{"name":"SHA256SUMS.txt","browser_download_url":%q}]}`,
				tag, srv.URL+"/bin", srv.URL+"/sums")
		case "/bin":
			fmt.Fprint(w, script)
		case "/sums":
			fmt.Fprintf(w, "%s  corepanel-linux-amd64\n", hexsum)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newUpd(t *testing.T, srvURL, cur string) (*Updater, string, *int) {
	t.Helper()
	old := latestURL
	latestURL = srvURL + "/latest"
	t.Cleanup(func() { latestURL = old })
	dir := t.TempDir()
	exe := filepath.Join(dir, "corepanel")
	os.WriteFile(exe, []byte("#!/bin/sh\necho "+cur+"\n"), 0o755)
	restarts := 0
	u := New(cur, platform.Info{OS: platform.OpenWrt, Arch: "amd64"}, func() *model.Settings { return model.Default() }, func() error { restarts++; return nil })
	u.ExePath = func() (string, error) { return exe, nil }
	return u, exe, &restarts
}

func wait(t *testing.T, u *Updater) State {
	t.Helper()
	for i := 0; i < 100; i++ {
		if s := u.State(); s.Job.Finished {
			return s
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("обновление не завершилось")
	return State{}
}

func TestCheckAndApply(t *testing.T) {
	srv := fakeRelease(t, "v0.2.0", "#!/bin/sh\necho 0.2.0\n", false)
	u, exe, restarts := newUpd(t, srv.URL, "0.1.0")
	info := u.Check(t.Context())
	if !info.Available || !info.CanApply || info.Latest != "0.2.0" {
		t.Fatalf("проверка: %+v", info)
	}
	if err := u.Apply(); err != nil {
		t.Fatal(err)
	}
	s := wait(t, u)
	if s.Job.Error != "" {
		t.Fatal(s.Job.Error)
	}
	b, _ := os.ReadFile(exe)
	if !strings.Contains(string(b), "0.2.0") || *restarts != 1 {
		t.Fatalf("файл не заменён или не было перезапуска: %q restarts=%d", b, *restarts)
	}
}

func TestApplyRejectsBadChecksum(t *testing.T) {
	srv := fakeRelease(t, "v0.2.0", "#!/bin/sh\necho 0.2.0\n", true)
	u, exe, restarts := newUpd(t, srv.URL, "0.1.0")
	u.Check(t.Context())
	u.Apply()
	s := wait(t, u)
	if !strings.Contains(s.Job.Error, "контрольная сумма") {
		t.Fatalf("ожидался отказ по сумме: %q", s.Job.Error)
	}
	b, _ := os.ReadFile(exe)
	if strings.Contains(string(b), "0.2.0") || *restarts != 0 {
		t.Fatal("файл не должен меняться")
	}
	if _, err := os.Stat(exe + ".new"); err == nil {
		t.Fatal("временный файл должен удаляться")
	}
}

func TestNoUpdateWhenSame(t *testing.T) {
	srv := fakeRelease(t, "v0.1.0", "x", false)
	u, _, _ := newUpd(t, srv.URL, "0.1.0")
	if info := u.Check(t.Context()); info.Available {
		t.Fatalf("та же версия: %+v", info)
	}
	if err := u.Apply(); err == nil {
		t.Fatal("Apply без обновления должен отказывать")
	}
}
