package sysauth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckVectors(t *testing.T) {
	for _, h := range []string{
		"$1$abcdefgh$irWbblnpmw.5z7wgBnprh0",
		"$5$abcdefgh$qdvcTv0LZNZdlT5oJZ49o5SQ8X7bA9/X.MJjvjS5cW8",
		"$6$abcdefgh$3rj1vTLX64btReFsM4MQ22otcD40l7vbtw7qCyr0dxc4kxNmgx53xVM8gWiLYbCqTHTbXFaVFU7ZT28pnvdyu0",
	} {
		if ok, err := Check("test", h); !ok || err != nil {
			t.Errorf("%s: %v %v", h[:4], ok, err)
		}
		if ok, _ := Check("wrong", h); ok {
			t.Errorf("%s: принят неверный пароль", h[:4])
		}
	}
	if _, err := Check("x", "$y$j9T$abc$def"); err != ErrUnsupported {
		t.Error("yescrypt должен давать ErrUnsupported")
	}
}

func TestVerifyFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "shadow")
	os.WriteFile(f, []byte("daemon:*:0:0:::::\nroot:$1$abcdefgh$irWbblnpmw.5z7wgBnprh0:19000:0:99999:7:::\n"), 0o600)
	old := ShadowFiles
	ShadowFiles = []string{f}
	defer func() { ShadowFiles = old }()
	if ok, err := Verify("root", "test"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := Verify("root", "nope"); ok {
		t.Fatal("неверный пароль принят")
	}
	os.WriteFile(f, []byte("root:::0:0:::::\n"), 0o600)
	if ok, err := Verify("root", "x"); ok || err == nil {
		t.Fatal("пустой пароль root должен давать ошибку")
	}
}
