package gen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// O — словарь с сохранением порядка ключей. Из него одинаково собираются
// и JSON (sing-box), и YAML (Mihomo), поэтому генераторы пишутся один раз.
type O struct {
	keys []string
	vals map[string]any
}

func NewO() *O { return &O{vals: map[string]any{}} }

// Set задаёт значение (заменяет, сохраняя исходную позицию ключа).
func (o *O) Set(k string, v any) *O {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

// Opt задаёт значение только если оно не «нулевое».
func (o *O) Opt(k string, v any) *O {
	if isZero(v) {
		return o
	}
	return o.Set(k, v)
}

func (o *O) Get(k string) (any, bool) { v, ok := o.vals[k]; return v, ok }

func (o *O) Keys() []string { return append([]string(nil), o.keys...) }

func (o *O) Delete(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, kk := range o.keys {
		if kk == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *O) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		vb, err := marshalNoEscape(o.vals[k])
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func marshalNoEscape(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// JSON возвращает красиво отформатированный JSON.
func JSON(v any) ([]byte, error) {
	raw, err := marshalNoEscape(v)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func isZero(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String, reflect.Slice, reflect.Map:
		return rv.Len() == 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() == 0
	case reflect.Bool:
		return !rv.Bool()
	case reflect.Float32, reflect.Float64:
		return rv.Float() == 0
	case reflect.Ptr:
		if rv.IsNil() {
			return true
		}
		if o, ok := v.(*O); ok {
			return len(o.keys) == 0
		}
	}
	return false
}

// ---------- слияние пользовательских добавок ----------

// Merge глубоко сливает src в dst. Массивы заменяются, а ключ с префиксом «+»
// (например "+outbounds") дописывает элементы в конец существующего массива.
func Merge(dst *O, src map[string]any) {
	keys := make([]string, 0, len(src))
	for k := range src {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := src[k]
		if strings.HasPrefix(k, "+") {
			key := k[1:]
			add, ok := v.([]any)
			if !ok {
				add = []any{v}
			}
			cur, _ := dst.Get(key)
			dst.Set(key, append(toAnySlice(cur), add...))
			continue
		}
		if sm, ok := v.(map[string]any); ok {
			if cur, ok := dst.Get(k); ok {
				if co, ok := cur.(*O); ok {
					Merge(co, sm)
					continue
				}
			}
			n := NewO()
			Merge(n, sm)
			dst.Set(k, n)
			continue
		}
		dst.Set(k, normalizeAny(v))
	}
}

func normalizeAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		n := NewO()
		Merge(n, t)
		return n
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = normalizeAny(e)
		}
		return out
	}
	return v
}

func toAnySlice(v any) []any {
	if v == nil {
		return nil
	}
	if a, ok := v.([]any); ok {
		return a
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice {
		return []any{v}
	}
	out := make([]any, rv.Len())
	for i := range out {
		out[i] = rv.Index(i).Interface()
	}
	return out
}

// ---------- YAML ----------

var plainKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
var yamlWords = map[string]bool{"y": true, "n": true, "yes": true, "no": true, "true": true, "false": true, "on": true, "off": true, "null": true}

func yamlKey(k string) string {
	if plainKey.MatchString(k) && !yamlWords[strings.ToLower(k)] {
		return k
	}
	return yamlString(k)
}

func yamlString(s string) string {
	b, _ := marshalNoEscape(s)
	return string(b)
}

// YAML сериализует значение в YAML (двойные кавычки для всех строк — это безопасно для любых данных).
func YAML(v any) string {
	var b strings.Builder
	writeYAML(&b, v, 0)
	return b.String()
}

func isScalar(v any) bool {
	switch t := v.(type) {
	case nil, string, bool, int, int8, int16, int32, int64, uint, uint16, uint32, uint64, float32, float64:
		return true
	case *O:
		return false
	default:
		_ = t
		rk := reflect.ValueOf(v).Kind()
		return rk != reflect.Slice && rk != reflect.Map && rk != reflect.Array
	}
}

func scalar(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return yamlString(t)
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(t)
	}
}

func isEmptyContainer(v any) (string, bool) {
	switch t := v.(type) {
	case *O:
		if len(t.keys) == 0 {
			return "{}", true
		}
	default:
		rv := reflect.ValueOf(v)
		if (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Map) && rv.Len() == 0 {
			if rv.Kind() == reflect.Map {
				return "{}", true
			}
			return "[]", true
		}
	}
	return "", false
}

func asMap(v any) (*O, bool) {
	switch t := v.(type) {
	case *O:
		return t, true
	case map[string]any:
		n := NewO()
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			n.Set(k, t[k])
		}
		return n, true
	}
	return nil, false
}

func writeYAML(b *strings.Builder, v any, indent int) {
	pad := strings.Repeat(" ", indent)
	if m, ok := asMap(v); ok {
		for _, k := range m.keys {
			val := m.vals[k]
			if e, ok := isEmptyContainer(val); ok {
				fmt.Fprintf(b, "%s%s: %s\n", pad, yamlKey(k), e)
				continue
			}
			if isScalar(val) {
				fmt.Fprintf(b, "%s%s: %s\n", pad, yamlKey(k), scalar(val))
				continue
			}
			fmt.Fprintf(b, "%s%s:\n", pad, yamlKey(k))
			writeYAML(b, val, indent+2)
		}
		return
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
		for i := 0; i < rv.Len(); i++ {
			item := rv.Index(i).Interface()
			if isScalar(item) {
				fmt.Fprintf(b, "%s- %s\n", pad, scalar(item))
				continue
			}
			if e, ok := isEmptyContainer(item); ok {
				fmt.Fprintf(b, "%s- %s\n", pad, e)
				continue
			}
			var sub strings.Builder
			writeYAML(&sub, item, indent+2)
			s := sub.String()
			// первая строка вложенного блока получает маркер «- » вместо отступа
			s = pad + "- " + strings.TrimPrefix(s, strings.Repeat(" ", indent+2))
			b.WriteString(s)
		}
		return
	}
	fmt.Fprintf(b, "%s%s\n", pad, scalar(v))
}
