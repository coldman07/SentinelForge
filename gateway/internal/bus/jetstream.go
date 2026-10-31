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

// Consume delivers stream events to handler. A message is acknowledged only
// after handler succeeds; failed writes are retried after a short delay.
func (p *JetStreamPublisher) Consume(
	ctx context.Context,
	durableName string,
	handler func(context.Context, []byte) error,
) error {
	subscription, err := p.js.PullSubscribe(
		subjectRoot+".>",
		durableName,
		nats.ManualAck(),
		nats.AckWait(30*time.Second),
	)
	if err != nil {
		return fmt.Errorf("subscribe to JetStream: %w", err)
	}

	for ctx.Err() == nil {
		messages, err := subscription.Fetch(1, nats.MaxWait(time.Second))
		if errors.Is(err, nats.ErrTimeout) {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("fetch JetStream message: %w", err)
		}

		for _, message := range messages {
			if err := handler(ctx, message.Data); err != nil {
				if nakErr := message.NakWithDelay(5 * time.Second); nakErr != nil {
					return fmt.Errorf("reject failed event write: %w (write error: %v)", nakErr, err)
				}
				continue
			}
			if err := message.Ack(); err != nil {
				return fmt.Errorf("acknowledge stored event: %w", err)
			}
		}
	}
	return nil
}
