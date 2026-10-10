// Package store хранит настройки панели и учётные данные на диске.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"corepanel/internal/model"
)

// Store — хранилище настроек (settings.json) и параметров панели (panel.json).
type Store struct {
	dir string
	mu  sync.RWMutex
	set *model.Settings
	pnl *Panel
}

// Panel — параметры самой панели (не ядра).
// Вход по умолчанию выключен; если включён, проверяется пароль root (как для SSH).
type Panel struct {
	Listen      string `json:"listen"`
	AuthEnabled bool   `json:"auth_enabled"`
	Epoch       string `json:"epoch"` // меняется при включении/выключении входа и обнуляет все сессии
}

// Open читает настройки из каталога dir (создаёт при отсутствии).
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st := &Store{dir: dir}
	set := model.Default()
	if b, err := os.ReadFile(filepath.Join(dir, "settings.json")); err == nil {
		if err := json.Unmarshal(b, set); err != nil {
			return nil, errors.New("settings.json повреждён: " + err.Error() + " (копия предыдущей версии — settings.json.bak)")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	set.Normalize()
	st.set = set

	if b, err := os.ReadFile(filepath.Join(dir, "panel.json")); err == nil {
		var p Panel
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, errors.New("panel.json повреждён: " + err.Error())
		}
		st.pnl = &p
	}
	return st, nil
}

// Dir — каталог данных.
func (st *Store) Dir() string { return st.dir }

// Get возвращает копию текущих настроек.
func (st *Store) Get() *model.Settings {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return clone(st.set)
}

func clone(s *model.Settings) *model.Settings {
	b, _ := json.Marshal(s)
	var c model.Settings
	_ = json.Unmarshal(b, &c)
	c.Normalize()
	return &c
}

// Set сохраняет настройки (предыдущая версия остаётся в settings.json.bak).
func (st *Store) Set(s *model.Settings) error {
	s = clone(s)
	st.mu.Lock()
	defer st.mu.Unlock()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(st.dir, "settings.json")
	if old, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".bak", old, 0o600)
	}
	if err := writeFile(path, b); err != nil {
		return err
	}
	st.set = s
	return nil
}

func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---------- учётные данные панели ----------

// Panel возвращает параметры панели; при первом запуске создаёт их (вход выключен).
func (st *Store) Panel(defaultListen string) (Panel, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pnl != nil && st.pnl.Epoch != "" {
		return *st.pnl, nil
	}
	np := Panel{Listen: defaultListen, Epoch: RandomToken(8)}
	if st.pnl != nil { // panel.json от старой версии: сохраняем адрес, вход выключен
		np.Listen = st.pnl.Listen
	}
	if err := st.savePanelLocked(&np); err != nil {
		return Panel{}, err
	}
	st.pnl = &np
	return np, nil
}

func (st *Store) savePanelLocked(p *Panel) error {
	b, _ := json.MarshalIndent(p, "", "  ")
	return writeFile(filepath.Join(st.dir, "panel.json"), b)
}

// SetAuth включает или выключает вход по паролю root. Смена состояния завершает все сессии.
func (st *Store) SetAuth(enabled bool) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pnl == nil {
		return errors.New("панель не инициализирована")
	}
	np := *st.pnl
	np.AuthEnabled = enabled
	np.Epoch = RandomToken(8)
	if err := st.savePanelLocked(&np); err != nil {
		return err
	}
	st.pnl = &np
	return nil
}

// SetListen меняет адрес прослушивания (вступит в силу после перезапуска).
func (st *Store) SetListen(addr string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pnl == nil {
		return errors.New("панель не инициализирована")
	}
	np := *st.pnl
	np.Listen = addr
	if err := st.savePanelLocked(&np); err != nil {
		return err
	}
	st.pnl = &np
	return nil
}

// PanelInfo — текущие параметры без пароля.
func (st *Store) PanelInfo() Panel {
	st.mu.RLock()
	defer st.mu.RUnlock()
	if st.pnl == nil {
		return Panel{}
	}
	return *st.pnl
}

// RandomToken возвращает случайную строку из n байт (hex-кодирование).
func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
