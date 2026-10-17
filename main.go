package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/api"
)

//go:embed web/dist/*
var embeddedDist embed.FS

func main() {
	server, err := api.NewAppServer()
	if err != nil {
		log.Fatalf("[Init Error] %v", err)
	}
	defer server.Proxy().Close()

	ctx := context.Background()
	if !server.Proxy().IsRemoteEnabled() {
		demoLic, _ := server.Proxy().CreateLicense(ctx, 30, 1)
		log.Printf("[Init] Pre-seeded demo license key: %s (Local Standalone Mode)", demoLic.LicenseKey)
	} else {
		log.Printf("[Init] Remote Google Apps Script Web App active: %s", server.Proxy().WebAppURL())
	}

	subFS, err := fs.Sub(embeddedDist, "web/dist")
	if err != nil {
		log.Fatalf("Failed to create sub filesystem: %v", err)
	}

	handler := server.Routes(subFS)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9082"
	}

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("  Sheet-License-Broker Server active on http://%s (v1.5.0)", addr)

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
