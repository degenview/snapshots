// Command snapshots is the DegenView snapshot host.
//
//	snapshots [serve]    run the server (default)
//	snapshots healthcheck  probe /healthz on the local server (for container health checks)
//	snapshots version
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/degenview/snapshots/internal/auth"
	"github.com/degenview/snapshots/internal/config"
	"github.com/degenview/snapshots/internal/db"
	"github.com/degenview/snapshots/internal/janitor"
	"github.com/degenview/snapshots/internal/repo"
	"github.com/degenview/snapshots/internal/server"
	"github.com/degenview/snapshots/internal/settings"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		if err := serve(); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "healthcheck":
		if err := healthcheck(); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "usage: %s [serve|healthcheck|version]\n", os.Args[0])
		os.Exit(2)
	}
}

func serve() error {
	cfg, err := config.LoadEnv()
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "text" {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	log := slog.New(handler)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var database *db.DB
	if cfg.IsPostgres() {
		database, err = db.OpenPostgres(cfg.DatabaseURL)
	} else {
		database, err = db.OpenSQLite(cfg.SQLitePath())
	}
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	r := repo.New(database)

	key, err := settings.ResolveKey(cfg)
	if err != nil {
		return err
	}
	srv, err := server.New(server.Deps{
		Config: cfg, Repo: r, Settings: settings.NewStore(r, key), Log: log, Version: version,
		SetupToken: cfg.SetupToken,
	})
	if err != nil {
		return err
	}
	if err := srv.Init(ctx); err != nil {
		return err
	}
	if !srv.Configured() {
		if cfg.SetupToken != "" {
			log.Warn("first-run setup required: open /setup in a browser and enter your SETUP_TOKEN")
		} else {
			token, err := auth.NewSetupToken()
			if err != nil {
				return err
			}
			srv.SetSetupToken(token)
			log.Warn("first-run setup required: open /setup in a browser", "setup token", token,
				"hint", "set SETUP_TOKEN to choose your own")
		}
	}

	j := &janitor.Janitor{Repo: r, Store: srv.Store, Prune: srv.PruneSessions, Log: log, Interval: time.Minute}
	go j.Run(ctx)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(handler, slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "version", version, "database", dbKind(cfg))
		errc <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func dbKind(cfg *config.Config) string {
	if cfg.IsPostgres() {
		return "postgres"
	}
	return "sqlite"
}

// healthcheck asks the local server for /healthz. It exists because the
// container image has no shell or curl.
func healthcheck() error {
	cfg, err := config.LoadEnv()
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(hreq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
