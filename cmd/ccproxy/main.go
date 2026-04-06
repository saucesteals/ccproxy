package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/saucesteals/ccproxy/internal/auth"
	"github.com/saucesteals/ccproxy/internal/proxy"
)

func main() {
	listenAddr := envOr("LISTEN_ADDR", ":8080")
	authToken := envOr("AUTH_TOKEN", "")
	configDir := envOr("CONFIG_DIR", os.Getenv("HOME")+"/.ccproxy")
	ccVersion := envOr("CC_VERSION", "2.1.92")
	upstream := envOr("UPSTREAM", "https://api.anthropic.com")

	authStore := auth.NewStore(configDir, ccVersion)
	if err := authStore.Load(); err != nil {
		slog.Warn("auth not loaded (run auth first)", "error", err)
	} else {
		id := authStore.Identity()
		slog.Info("auth loaded", "uuid", id.AccountUUID[:min(8, len(id.AccountUUID))]+"...", "email", id.Email)
		authStore.StartRefreshLoop()
	}

	handler := proxy.New(proxy.Config{
		AuthToken: authToken,
		Upstream:  upstream,
		Version:   ccVersion,
		Auth:      authStore,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	slog.Info("ccproxy listening", "addr", listenAddr, "upstream", upstream, "version", ccVersion)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
