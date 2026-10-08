// corepanel — веб-панель настройки sing-box и Mihomo для роутеров OpenWrt и Keenetic.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"corepanel/internal/features"
	"corepanel/internal/installer"
	"corepanel/internal/platform"
	"corepanel/internal/server"
	"corepanel/internal/store"
	"corepanel/internal/supervisor"
)

var version = "dev"

const usage = `corepanel %s — панель sing-box / Mihomo для OpenWrt и Keenetic

Использование:
  corepanel [run] [-listen host:port]   запустить панель (по умолчанию)
  corepanel passwd [пароль]             сбросить пароль администратора
  corepanel features-md                 вывести справочник возможностей в Markdown
  corepanel version

Переменные окружения: COREPANEL_DIR, COREPANEL_BIN_DIR, COREPANEL_PLATFORM (openwrt|keenetic|linux)
`

func main() {
	cmd := "run"
	args := os.Args[1:]
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run":
		run(args)
	case "passwd":
		pw := ""
		if len(args) > 0 {
			pw = args[0]
		} else {
			pw = store.RandomToken(6)
			fmt.Println("Новый пароль:", pw)
		}
		if len(pw) < 6 {
			fatal(errors.New("пароль должен быть не короче 6 символов"))
		}
		if err := store.ResetPassword(platform.Detect().DataDir, pw); err != nil {
			fatal(err)
		}
		fmt.Println("Пароль администратора (admin) изменён.")
	case "features-md":
		fmt.Print(features.Markdown())
	case "version", "-v", "--version":
		fmt.Println(version)
	default:
		fmt.Printf(usage, version)
		os.Exit(2)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ошибка:", err)
	os.Exit(1)
}

func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	listen := fs.String("listen", "", "адрес панели (по умолчанию из настроек, затем :8088)")
	_ = fs.Parse(args)

	info := platform.Detect()
	st, err := store.Open(info.DataDir)
	if err != nil {
		fatal(err)
	}
	pnl, pw, err := st.Panel(":8088")
	if err != nil {
		fatal(err)
	}
	if pw != "" {
		fmt.Printf("Первый запуск. Вход: admin / %s (пароль потребуется сменить)\n", pw)
	}
	if *listen != "" {
		pnl.Listen = *listen
	}

	inst := installer.New(info)
	sup := supervisor.New(info, inst, st.Get)
	srv := server.New(version, info, st, sup, inst)

	if st.Get().Autostart {
		go func() {
			if err := sup.Start(st.Get()); err != nil {
				sup.Logs.Add("[panel] автозапуск не удался: " + err.Error())
			}
		}()
	}

	hs := &http.Server{Addr: pnl.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		fmt.Printf("corepanel %s (%s/%s) слушает %s, данные: %s\n", version, info.OSName, info.Arch, pnl.Listen, info.DataDir)
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = sup.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = hs.Shutdown(ctx)
}
