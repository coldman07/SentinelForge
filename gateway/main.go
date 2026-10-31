package main

import (
	"log"
	"net/http"
	"os"
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
		Handler:           ingest.NewHandlerWithEvents(publisher, clickHouseStore),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("gateway listening on %s", address)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
