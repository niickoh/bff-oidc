package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/niickoh/bff-oidc/internal/app"
	"github.com/niickoh/bff-oidc/internal/config"
	"github.com/niickoh/bff-oidc/internal/oidcclient"
	"github.com/niickoh/bff-oidc/internal/session"
)

func main() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	oidc, err := oidcclient.New(context.Background(), cfg)
	if err != nil {
		log.Fatalf("init oidc client: %v", err)
	}

	server := app.NewServer(cfg, oidc, session.NewStore())

	httpServer := &http.Server{
		Addr:              cfg.AppAddr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("bff-oidc listening on %s", cfg.AppAddr)
	log.Fatal(httpServer.ListenAndServe())
}
