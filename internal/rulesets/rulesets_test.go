package rulesets

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"corepanel/internal/model"
)

func TestConvert(t *testing.T) {
	in := "\xef\xbb\xbf# комментарий\nYouTube.com\n.example.org\n*.wild.net\n1.2.3.0/24\n8.8.8.8\n2001:db8::/32\nfull:exact.host.io\nkeyword:casino\nDOMAIN-SUFFIX,clash.dev,no-resolve\nIP-CIDR,10.0.0.0/8,no-resolve\nyoutube.com\nнедомен\n// c\n"
	b, n := Convert(in)
	var out struct {
		Rules []map[string][]string `json:"rules"`
	}
	if err := json.Unmarshal(b, &out); err != nil || len(out.Rules) != 1 {
		t.Fatalf("%v %s", err, b)
	}
	r := out.Rules[0]
	want := map[string][]string{
		"domain_suffix":  {"youtube.com", "example.org", "wild.net", "clash.dev"},
		"domain":         {"exact.host.io"},
		"domain_keyword": {"casino"},
		"ip_cidr":        {"1.2.3.0/24", "8.8.8.8/32", "2001:db8::/32", "10.0.0.0/8"},
	}
	for k, v := range want {
		if len(r[k]) != len(v) {
			t.Fatalf("%s: %v, ждали %v", k, r[k], v)
		}
		for i := range v {
			if r[k][i] != v[i] {
				t.Fatalf("%s: %v, ждали %v", k, r[k], v)
			}
		}
	}
	if n != 10 {
		t.Fatalf("n=%d", n)
	}
	if b, n := Convert("# пусто\n"); n != 0 || string(b) != `{"rules":[],"version":2}` {
		t.Fatalf("%d %s", n, b)
	}
}

func TestPrepare(t *testing.T) {
	dir := t.TempDir()
	sets := []model.RuleSet{{Name: "set-2", URL: "https://x.test/inside-raw.lst"}, {Name: "bin", URL: "https://x.test/a.srs"}}
	calls := 0
	ok := func(ctx context.Context, u string) ([]byte, error) { calls++; return []byte("a.com\nb.org\n"), nil }
	if w := Prepare(context.Background(), dir, sets, ok, false); len(w) != 0 {
		t.Fatal(w)
	}
	b, err := os.ReadFile(filepath.Join(dir, "rulesets", "set-2.json"))
	if err != nil || len(b) == 0 {
		t.Fatal(err)
	}
	Prepare(context.Background(), dir, sets, ok, false)
	if calls != 1 {
		t.Fatalf("свежий набор скачан повторно: %d", calls)
	}
	// ошибка скачивания: старая копия остаётся, повтор будет при следующем проходе
	bad := func(ctx context.Context, u string) ([]byte, error) { return nil, context.DeadlineExceeded }
	dir2 := t.TempDir()
	if w := Prepare(context.Background(), dir2, sets, bad, false); len(w) != 1 {
		t.Fatal(w)
	}
	if _, err := os.Stat(filepath.Join(dir2, "rulesets", "set-2.json")); err != nil {
		t.Fatal("ядру нужен хотя бы пустой файл")
	}
	Prepare(context.Background(), dir2, sets, ok, false)
	if calls != 2 {
		t.Fatal("после неудачи скачивание должно повториться")
	}
}

func TestIsText(t *testing.T) {
	for u, want := range map[string]bool{"https://a/b.lst": true, "https://a/b.txt": true, "https://a/b.srs": false, "https://a/b": false} {
		if IsText(model.RuleSet{URL: u}) != want {
			t.Fatal(u)
		}
	}
	if !IsText(model.RuleSet{URL: "https://a/b", Format: "text"}) || IsText(model.RuleSet{URL: "https://a/b.lst", Format: "srs"}) {
		t.Fatal("явный формат главнее")
	}
}
