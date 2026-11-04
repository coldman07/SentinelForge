package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/coldman07/SentinelForge/gateway/internal/bus"
	"github.com/coldman07/SentinelForge/gateway/internal/store"
)

func main() {
	natsURL := envOr("SF_NATS_URL", "nats://127.0.0.1:4222")
	clickHouseURL := envOr("SF_CLICKHOUSE_URL", "http://127.0.0.1:8123")
	clickHouseUser := os.Getenv("SF_CLICKHOUSE_USER")
	clickHousePassword := os.Getenv("SF_CLICKHOUSE_PASSWORD")

	store, err := store.NewClickHouseStore(clickHouseURL, clickHouseUser, clickHousePassword)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := store.EnsureSchema(ctx); err != nil {
		log.Fatalf("initialize ClickHouse event store: %v", err)
	}

	publisher, connection, err := bus.Connect(natsURL)
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Drain()
	log.Printf("event store consuming events, alerts, and incidents and writing to %s", clickHouseURL)
	consumerErrors := make(chan error, 3)
	go func() {
		consumerErrors <- publisher.Consume(ctx, "EVENT_STORE", store.InsertEvent)
	}()
	go func() {
		consumerErrors <- publisher.ConsumeSubject(
			ctx,
			"sentinelforge.incidents.v1.>",
			"INCIDENT_STORE",
			store.InsertIncident,
		)
	}()
	go func() {
		consumerErrors <- publisher.ConsumeSubject(
			ctx,
			"sentinelforge.alerts.v1.>",
			"ALERT_STORE",
			store.InsertAlert,
		)
	}()

	select {
	case <-ctx.Done():
		log.Print("event store shutting down")
	case err := <-consumerErrors:
		stop()
		if err != nil {
			log.Fatalf("event-store consumer stopped: %v", err)
		}
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
