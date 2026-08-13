// Command head-control is a self-hosted admin UI for headscale v0.29.x.
// It serves an embedded web frontend and a same-origin JSON API that proxies
// the headscale REST API — the headscale API key never reaches the browser.
//
// Configuration is environment-variables only; see the README. Subcommands:
//
//	head-control                 run the server (default)
//	head-control hash-password   read a password from stdin, print bcrypt hash
//	head-control version         print the version
package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/panagiotis1226/head-control/internal/auth"
	"github.com/panagiotis1226/head-control/internal/config"
	"github.com/panagiotis1226/head-control/internal/hsclient"
	"github.com/panagiotis1226/head-control/internal/server"
	"github.com/panagiotis1226/head-control/internal/store"
)

var version = "dev" // stamped via -ldflags "-X main.version=..."

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "hash-password":
			hashPassword()
			return
		case "version", "--version", "-v":
			fmt.Println("head-control", version)
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown subcommand %q (available: hash-password, version)\n", os.Args[1])
			os.Exit(2)
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "head-control:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	log := newLogger(cfg)
	server.Version = version

	var opts []hsclient.Option
	if cfg.CAFile != "" {
		opts = append(opts, hsclient.WithCACert(cfg.CAFile))
	}
	hs, err := hsclient.New(cfg.HeadscaleURL, cfg.APIKey, opts...)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("creating DATA_DIR %s: %w", cfg.DataDir, err)
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return server.New(cfg, log, hs, st).Run(ctx)
}

func newLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.ToLower(cfg.LogFormat) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}

func hashPassword() {
	fmt.Fprint(os.Stderr, "Password: ")
	reader := bufio.NewReader(os.Stdin)
	pw, err := reader.ReadString('\n')
	if err != nil && pw == "" {
		fmt.Fprintln(os.Stderr, "reading password:", err)
		os.Exit(1)
	}
	pw = strings.TrimRight(pw, "\r\n")
	if len(pw) < 8 {
		fmt.Fprintln(os.Stderr, "refusing to hash a password shorter than 8 characters")
		os.Exit(1)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hashing:", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}
