package bus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/coldman07/SentinelForge/gateway/internal/ingest"
	"github.com/nats-io/nats.go"
)

const (
	streamName  = "SENTINELFORGE_EVENTS"
	subjectRoot = "sentinelforge.events.v1"
)

// JetStreamPublisher publishes validated events to a durable NATS stream.
type JetStreamPublisher struct {
	js nats.JetStreamContext
}

func Connect(url string) (*JetStreamPublisher, *nats.Conn, error) {
	conn, err := nats.Connect(url,
		nats.Name("sentinelforge-gateway"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to NATS: %w", err)
	}

	js, err := conn.JetStream()
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("initialize JetStream client: %w", err)
	}
	if _, err := js.StreamInfo(streamName); errors.Is(err, nats.ErrStreamNotFound) {
		if _, addErr := js.AddStream(&nats.StreamConfig{
			Name:      streamName,
			Subjects:  []string{subjectRoot + ".>"},
			Retention: nats.LimitsPolicy,
			Storage:   nats.FileStorage,
		}); addErr != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("ensure JetStream stream: %w", addErr)
		}
	} else if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("inspect JetStream stream: %w", err)
	}

	return &JetStreamPublisher{js: js}, conn, nil
}

func (p *JetStreamPublisher) Publish(event ingest.Event) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := p.js.Publish(subjectRoot+"."+event.Category, body, nats.Context(ctx)); err != nil {
		return fmt.Errorf("publish event: %w", err)
	}
	return nil
}
