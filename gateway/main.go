package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coldman07/SentinelForge/gateway/internal/bus"
	"github.com/coldman07/SentinelForge/gateway/internal/ingest"
	"github.com/coldman07/SentinelForge/gateway/internal/store"
)

func main() {
	address := os.Getenv("SF_GATEWAY_ADDR")
	if address == "" {
		address = ":8080"
	}
	natsURL := os.Getenv("SF_NATS_URL")
	if natsURL == "" {
		natsURL = "nats://127.0.0.1:4222"
	}
	clickHouseURL := os.Getenv("SF_CLICKHOUSE_URL")
	if clickHouseURL == "" {
		clickHouseURL = "http://127.0.0.1:8123"
	}
	clickHouseStore, err := store.NewClickHouseStore(
		clickHouseURL,
		os.Getenv("SF_CLICKHOUSE_USER"),
		os.Getenv("SF_CLICKHOUSE_PASSWORD"),
	)
	if err != nil {
		log.Fatal(err)
	}
	publisher, connection, err := bus.Connect(natsURL)
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Drain()

	server := &http.Server{
		Addr:              address,
		Handler:           ingest.NewHandlerWithServices(publisher, clickHouseStore, clickHouseStore, clickHouseStore),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("gateway listening on %s", address)
	if os.Getenv("SF_MTLS_REQUIRED") == "true" {
		certFile, keyFile, caFile := os.Getenv("SF_GATEWAY_CERT_FILE"), os.Getenv("SF_GATEWAY_KEY_FILE"), os.Getenv("SF_CLIENT_CA_FILE")
		if certFile == "" || keyFile == "" || caFile == "" {
			log.Fatal("SF_MTLS_REQUIRED needs SF_GATEWAY_CERT_FILE, SF_GATEWAY_KEY_FILE, and SF_CLIENT_CA_FILE")
		}
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatalf("read client CA: %v", err)
		}
		clientCAs := x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(caPEM) {
			log.Fatal("client CA file contains no certificates")
		}
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
		if !strings.HasPrefix(address, ":") && !strings.HasPrefix(address, "0.0.0.0:") {
			log.Printf("gateway TLS listener bound to %s", address)
		}
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
