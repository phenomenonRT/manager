// Package sysauth проверяет пароль пользователя root по файлам shadow роутера —
// тот же пароль, что и для входа по SSH.
package sysauth

import (
	"bufio"
	"errors"
	"os"
	"strings"
)

// ShadowFiles — где искать пароль root: OpenWrt, затем Entware (Keenetic).
var ShadowFiles = []string{"/etc/shadow", "/opt/etc/shadow"}

// Verify проверяет пароль root. Ошибка означает, что проверить нельзя
// (нет файла, пароль не задан или заблокирован, формат не поддерживается).
func Verify(user, pw string) (bool, error) {
	if pw == "" {
		return false, nil
	}
	var firstErr error
	for _, f := range ShadowFiles {
		h, err := rootHash(f, user)
		if err != nil {
			if firstErr == nil && !errors.Is(err, os.ErrNotExist) {
				firstErr = err
			}
			continue
		}
		okp, err := Check(pw, h)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if okp {
			return true, nil
		}
		firstErr = nil
		return false, nil
	}
	if firstErr == nil {
		firstErr = errors.New("у root не задан пароль (выполните по SSH команду passwd) или нет файла shadow")
	}
	return false, firstErr
}

func rootHash(path, user string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) > 1 && parts[0] == user {
			h := parts[1]
			if h == "" || h == "!" || h == "*" || h == "!!" || strings.HasPrefix(h, "!") && !strings.HasPrefix(h, "!$") {
				return "", errors.New("у пользователя root не задан пароль: выполните по SSH команду passwd")
			}
			return strings.TrimPrefix(h, "!"), nil
		}
	}
	return "", os.ErrNotExist
}
