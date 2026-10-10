package sysauth

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"hash"
	"strconv"
	"strings"
)

const b64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func enc24(sb *strings.Builder, b2, b1, b0 byte, n int) {
	w := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
	for ; n > 0; n-- {
		sb.WriteByte(b64[w&0x3f])
		w >>= 6
	}
}

// ErrUnsupported — формат хеша пароля не поддерживается.
var ErrUnsupported = errors.New("неподдерживаемый формат хеша пароля в shadow (поддерживаются $1$, $5$, $6$)")

// Check сравнивает пароль с записью shadow (md5-crypt, sha256-crypt, sha512-crypt).
func Check(pw, stored string) (bool, error) {
	var got string
	switch {
	case strings.HasPrefix(stored, "$1$"):
		salt := strings.SplitN(stored[3:], "$", 2)[0]
		if len(salt) > 8 {
			salt = salt[:8]
		}
		got = md5Crypt(pw, salt)
	case strings.HasPrefix(stored, "$5$"), strings.HasPrefix(stored, "$6$"):
		got = shaCrypt(pw, stored)
	default:
		return false, ErrUnsupported
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(stored)) == 1, nil
}

func md5Crypt(pw, salt string) string {
	p, s := []byte(pw), []byte(salt)
	alt := md5.Sum(append(append(append([]byte{}, p...), s...), p...))
	c := md5.New()
	c.Write(p)
	c.Write([]byte("$1$"))
	c.Write(s)
	for i := len(p); i > 0; i -= 16 {
		n := i
		if n > 16 {
			n = 16
		}
		c.Write(alt[:n])
	}
	for i := len(p); i > 0; i >>= 1 {
		if i&1 == 1 {
			c.Write([]byte{0})
		} else {
			c.Write(p[:1])
		}
	}
	fin := c.Sum(nil)
	for i := 0; i < 1000; i++ {
		d := md5.New()
		if i&1 == 1 {
			d.Write(p)
		} else {
			d.Write(fin)
		}
		if i%3 != 0 {
			d.Write(s)
		}
		if i%7 != 0 {
			d.Write(p)
		}
		if i&1 == 1 {
			d.Write(fin)
		} else {
			d.Write(p)
		}
		fin = d.Sum(nil)
	}
	var sb strings.Builder
	sb.WriteString("$1$" + salt + "$")
	enc24(&sb, fin[0], fin[6], fin[12], 4)
	enc24(&sb, fin[1], fin[7], fin[13], 4)
	enc24(&sb, fin[2], fin[8], fin[14], 4)
	enc24(&sb, fin[3], fin[9], fin[15], 4)
	enc24(&sb, fin[4], fin[10], fin[5], 4)
	enc24(&sb, 0, 0, fin[11], 2)
	return sb.String()
}

func shaCrypt(pw, stored string) string {
	is512 := stored[1] == '6'
	newH := func() hash.Hash {
		if is512 {
			return sha512.New()
		}
		return sha256.New()
	}
	rest := stored[3:]
	rounds, custom := 5000, false
	if strings.HasPrefix(rest, "rounds=") {
		end := strings.IndexByte(rest, '$')
		if end < 0 {
			return ""
		}
		n, err := strconv.Atoi(rest[7:end])
		if err != nil {
			return ""
		}
		if n < 1000 {
			n = 1000
		}
		if n > 999999999 {
			n = 999999999
		}
		rounds, custom = n, true
		rest = rest[end+1:]
	}
	salt := strings.SplitN(rest, "$", 2)[0]
	if len(salt) > 16 {
		salt = salt[:16]
	}
	p, s := []byte(pw), []byte(salt)
	sum := func(parts ...[]byte) []byte {
		h := newH()
		for _, x := range parts {
			h.Write(x)
		}
		return h.Sum(nil)
	}
	hl := newH().Size()
	b := sum(p, s, p)
	a := newH()
	a.Write(p)
	a.Write(s)
	n := len(p)
	for ; n > hl; n -= hl {
		a.Write(b)
	}
	a.Write(b[:n])
	for n = len(p); n > 0; n >>= 1 {
		if n&1 == 1 {
			a.Write(b)
		} else {
			a.Write(p)
		}
	}
	A := a.Sum(nil)
	dp := newH()
	for i := 0; i < len(p); i++ {
		dp.Write(p)
	}
	rep := func(src []byte, l int) []byte {
		out := make([]byte, 0, l)
		for len(out) < l {
			k := l - len(out)
			if k > len(src) {
				k = len(src)
			}
			out = append(out, src[:k]...)
		}
		return out
	}
	P := rep(dp.Sum(nil), len(p))
	ds := newH()
	for i := 0; i < 16+int(A[0]); i++ {
		ds.Write(s)
	}
	S := rep(ds.Sum(nil), len(s))
	for i := 0; i < rounds; i++ {
		h := newH()
		if i&1 == 1 {
			h.Write(P)
		} else {
			h.Write(A)
		}
		if i%3 != 0 {
			h.Write(S)
		}
		if i%7 != 0 {
			h.Write(P)
		}
		if i&1 == 1 {
			h.Write(A)
		} else {
			h.Write(P)
		}
		A = h.Sum(nil)
	}
	var sb strings.Builder
	sb.WriteString(stored[:3])
	if custom {
		sb.WriteString("rounds=" + strconv.Itoa(rounds) + "$")
	}
	sb.WriteString(salt + "$")
	if is512 {
		order := [][3]int{{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26}, {6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13}, {56, 14, 35}, {15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19}, {62, 20, 41}}
		for _, t := range order {
			enc24(&sb, A[t[0]], A[t[1]], A[t[2]], 4)
		}
		enc24(&sb, 0, 0, A[63], 2)
	} else {
		order := [][3]int{{0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23}, {24, 4, 14}, {15, 25, 5}, {6, 16, 26}, {27, 7, 17}, {18, 28, 8}, {9, 19, 29}}
		for _, t := range order {
			enc24(&sb, A[t[0]], A[t[1]], A[t[2]], 4)
		}
		enc24(&sb, 0, A[31], A[30], 3)
	}
	return sb.String()
}
