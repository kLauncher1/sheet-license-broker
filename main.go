package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/server"
)

//go:embed web/dist/*
var embeddedDist embed.FS

func main() {
	appServer, err := server.NewAppServer()
	if err != nil {
		log.Fatalf("[Init Error] %v", err)
	}
	defer appServer.Close()

	subFS, err := fs.Sub(embeddedDist, "web/dist")
	if err != nil {
		log.Fatalf("Failed to create sub filesystem: %v", err)
	}

	handler := appServer.SetupHandler(subFS)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9082"
	}

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("  Sheet-License-Broker Server active on http://%s (v1.7.0)", addr)

	s := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server exited unexpectedly: %v", err)
	}
}
