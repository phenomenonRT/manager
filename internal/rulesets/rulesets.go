// Package rulesets готовит текстовые списки доменов и подсетей для sing-box.
// Ядро sing-box умеет только бинарные (.srs) и JSON-наборы, поэтому обычный список
// «по домену в строке» панель сама скачивает, преобразует в JSON и подкладывает ядру как локальный набор.
package rulesets

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"corepanel/internal/model"
)

var unsafe = regexp.MustCompile(`[^A-Za-z0-9._!@-]`)

// File — путь файла набора относительно рабочего каталога ядра.
func File(name string) string { return "rulesets/" + unsafe.ReplaceAllString(name, "_") + ".json" }

// IsText говорит, нужно ли набору преобразование: явно выбранный формат text или файл .txt/.list/.lst.
func IsText(rs model.RuleSet) bool {
	if rs.Format != "" {
		return rs.Format == "text"
	}
	if u, err := url.Parse(rs.URL); err == nil {
		switch strings.ToLower(path.Ext(u.Path)) {
		case ".txt", ".list", ".lst":
			return true
		}
	}
	return false
}

var domainRe = regexp.MustCompile(`^[A-Za-z0-9_*.-]+$`)

// Convert превращает текстовый список в исходный JSON-набор sing-box и возвращает число записей.
// Понимает: домен в строке (подразумевается домен и все поддомены), IP и CIDR, а также префиксы
// full:/domain:/keyword:/regexp: и строки Clash вида DOMAIN-SUFFIX,example.com. Комментарии (#, //, ;) пропускаются.
func Convert(text string) ([]byte, int) {
	var suffix, full, keyword, regex, cidr []string
	seen := map[string]bool{}
	add := func(dst *[]string, v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		*dst = append(*dst, v)
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\xef\xbb\xbf"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") {
			continue
		}
		if i := strings.Index(line, " #"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		if k, v, ok := strings.Cut(line, ","); ok { // Clash: DOMAIN-SUFFIX,example.com[,no-resolve]
			v, _, _ = strings.Cut(v, ",")
			switch strings.ToUpper(strings.TrimSpace(k)) {
			case "DOMAIN-SUFFIX":
				add(&suffix, strings.ToLower(v))
			case "DOMAIN":
				add(&full, strings.ToLower(v))
			case "DOMAIN-KEYWORD":
				add(&keyword, strings.ToLower(v))
			case "IP-CIDR", "IP-CIDR6":
				add(&cidr, v)
			}
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok && !strings.Contains(v, ":") && !strings.Contains(k, ".") { // префиксы v2ray
			v = strings.ToLower(strings.TrimSpace(v))
			switch strings.ToLower(k) {
			case "domain":
				add(&suffix, v)
			case "full":
				add(&full, v)
			case "keyword":
				add(&keyword, v)
			case "regexp":
				add(&regex, strings.TrimSpace(strings.SplitN(line, ":", 2)[1]))
			}
			continue
		}
		if _, err := netip.ParsePrefix(line); err == nil {
			add(&cidr, line)
			continue
		}
		if a, err := netip.ParseAddr(line); err == nil {
			add(&cidr, a.String()+map[bool]string{true: "/32", false: "/128"}[a.Is4()])
			continue
		}
		line = strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(line, "*."), "."))
		if domainRe.MatchString(line) && strings.Contains(line, ".") {
			add(&suffix, line)
		}
	}
	rule := map[string]any{}
	set := func(k string, v []string) {
		if len(v) > 0 {
			rule[k] = v
		}
	}
	set("domain", full)
	set("domain_suffix", suffix)
	set("domain_keyword", keyword)
	set("domain_regex", regex)
	set("ip_cidr", cidr)
	n := len(full) + len(suffix) + len(keyword) + len(regex) + len(cidr)
	rules := []any{}
	if n > 0 {
		rules = append(rules, rule)
	}
	b, _ := json.Marshal(map[string]any{"version": 2, "rules": rules})
	return b, n
}

// Fetcher скачивает адрес целиком.
type Fetcher func(ctx context.Context, rawURL string) ([]byte, error)

// NewFetcher — скачивание напрямую (с зеркалом GitHub, если задано), затем через локальный прокси ядра.
func NewFetcher(mirror string, proxyPort int) Fetcher {
	get := func(ctx context.Context, u string, proxy *url.URL) ([]byte, error) {
		tr := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 20 * time.Second}
		if proxy != nil {
			tr.Proxy = http.ProxyURL(proxy)
		}
		cl := &http.Client{Transport: tr, Timeout: 45 * time.Second}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := cl.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	}
	return func(ctx context.Context, raw string) ([]byte, error) {
		u := raw
		if m := strings.TrimSpace(mirror); m != "" {
			if pu, err := url.Parse(raw); err == nil && (pu.Host == "raw.githubusercontent.com" || pu.Host == "github.com") {
				u = strings.TrimRight(m, "/") + "/" + raw
			}
		}
		b, err := get(ctx, u, nil)
		if err == nil || proxyPort <= 0 {
			return b, err
		}
		if p, perr := url.Parse(fmt.Sprintf("http://%s", net.JoinHostPort("127.0.0.1", fmt.Sprint(proxyPort)))); perr == nil {
			if b2, err2 := get(ctx, raw, p); err2 == nil {
				return b2, nil
			}
		}
		return nil, err
	}
}

// Prepare скачивает и преобразует текстовые наборы в dir/rulesets. Свежий файл (младше интервала, тот же адрес)
// не трогает, пока force=false. Возвращает предупреждения; при ошибке без старой копии пишет пустой набор,
// чтобы ядро всё равно запустилось.
func Prepare(ctx context.Context, dir string, sets []model.RuleSet, fetch Fetcher, force bool) []string {
	var warns []string
	for _, rs := range sets {
		if !IsText(rs) || rs.URL == "" {
			continue
		}
		file := filepath.Join(dir, filepath.FromSlash(File(rs.Name)))
		stamp := file + ".src"
		iv := time.Duration(rs.Interval) * time.Second
		if iv <= 0 {
			iv = 24 * time.Hour
		}
		if !force {
			if st, err := os.Stat(stamp); err == nil && time.Since(st.ModTime()) < iv {
				if old, _ := os.ReadFile(stamp); string(old) == rs.URL {
					continue
				}
			}
		}
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			warns = append(warns, fmt.Sprintf("набор «%s»: %v", rs.Name, err))
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		body, err := fetch(cctx, rs.URL)
		cancel()
		if err != nil {
			warns = append(warns, fmt.Sprintf("набор «%s»: не удалось скачать %s: %v", rs.Name, rs.URL, err))
			if _, e := os.Stat(file); e != nil {
				_ = os.WriteFile(file, []byte(`{"version":2,"rules":[]}`), 0o600)
			}
			continue
		}
		js, n := Convert(string(body))
		if n == 0 {
			warns = append(warns, fmt.Sprintf("набор «%s»: в списке %s не нашлось ни одного домена или подсети", rs.Name, rs.URL))
		}
		tmp := file + ".tmp"
		if err := os.WriteFile(tmp, js, 0o600); err == nil {
			err = os.Rename(tmp, file)
			if err == nil {
				_ = os.WriteFile(stamp, []byte(rs.URL), 0o600)
			}
		}
	}
	return warns
}
