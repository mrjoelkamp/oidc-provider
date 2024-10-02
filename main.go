package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/mrjoelkamp/oidc-provider/pkg/op"
)

const (
	host = "localhost"
	port = "5001"
)

func main() {
	config := &op.Config{
		LogLevel: "debug",
		KeyPath:  "./keys/priv.pem",
		Host:     host,
		Port:     port,
		Issuer:   fmt.Sprintf("http://%s:%s", host, port),
	}
	logger := op.NewLogger(config)
	logger.Info("issuer", "host", config.Issuer)
	storage := op.NewStorage()
	srv := op.NewServer(logger, config, storage)
	httpServer := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", host, port),
		Handler: srv,
	}

	log.Printf("listening on %s\n", httpServer.Addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "error listening and serving: %s\n", err)
	}
}
