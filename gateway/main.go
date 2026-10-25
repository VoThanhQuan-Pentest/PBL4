package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		client := &http.Client{Timeout: 2 * time.Second}
		response, err := client.Get("http://127.0.0.1:8082/healthz")
		if err != nil || response.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		response.Body.Close()
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var eventOutput io.Writer = os.Stdout
	var rotating *rotatingWriter
	if filename := os.Getenv("PREVENTION_EVENT_FILE"); filename != "" {
		file, err := newRotatingWriter(filename, preventionLogMaxBytes)
		if err != nil {
			slog.Error("Cannot open prevention event file", "exception_type", "filesystem")
			os.Exit(1)
		}
		rotating = file
		defer rotating.Close()
		eventOutput = file
	}
	app, err := newServer(
		env("PREVENTION_UPSTREAM", "http://nginx:80"),
		env("PREVENTION_POLICY_URL", "http://app:8080/internal/v1/prevention/policy"),
		env("PREVENTION_TOKEN_FILE", "/run/flare-secrets/prevention.token"),
		eventOutput,
	)
	if err != nil {
		slog.Error("Invalid gateway configuration", "exception_type", "configuration")
		os.Exit(1)
	}
	app.policyCache = os.Getenv("PREVENTION_POLICY_CACHE")
	if err := app.loadPolicy(); err != nil {
		slog.Error("Cannot restore last-known-good policy", "exception_type", "policy_cache")
		os.Exit(1)
	}
	defer app.redis.close()
	go app.poll(ctx)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				app.flushRateLimits(now)
			case <-ctx.Done():
				app.flushRateLimits(time.Now())
				return
			}
		}
	}()
	server := &http.Server{
		Addr:              env("PREVENTION_LISTEN", ":8082"),
		Handler:           app,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	management := &http.Server{
		Addr:              env("PREVENTION_MANAGEMENT_LISTEN", ":8089"),
		Handler:           http.HandlerFunc(app.ServeManagementHTTP),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	go func() {
		if err := management.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Management listener stopped", "exception_type", "listener")
			stop()
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = management.Shutdown(shutdown)
		_ = server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Gateway stopped", "exception_type", "listener")
		os.Exit(1)
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
