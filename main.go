package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mrjoelkamp/oidc-provider/pkg/op"
)

// host and port for the application
const (
	host = "localhost"
	port = "5001"
)

// main is the entrypoint for the application
func main() {
	// create app configuration
	// TODO: make configurable as args
	config := &op.Config{
		LogLevel: "debug",
		KeyPath:  "./keys/priv.pem",
		Host:     host,
		Port:     port,
		Issuer:   fmt.Sprintf("http://%s:%s", host, port),
	}

	// create logger, storage, and server
	logger := op.NewLogger(config)
	logger.Info("oidc provider", "iss", config.Issuer)
	storage := op.NewStorage()
	srv := op.NewServer(logger, config, storage)
	httpServer := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", host, port),
		Handler: srv,
	}

	// start server
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		log.Printf("listening on %s\n", httpServer.Addr)
		// TODO: provision with TLS certs to enable HTTPS
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "error listening and serving: %s\n", err)
		}
	}()

	// shutdown server gracefully
	<-sig
	fmt.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		fmt.Printf("shutdown failed: %v\n", err)
	}
	fmt.Println("stopped")
}
