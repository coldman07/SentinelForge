package bus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/coldman07/SentinelForge/gateway/internal/ingest"
	"github.com/nats-io/nats.go"
)

const (
	eventStreamName     = "SENTINELFORGE_EVENTS"
	eventSubjectRoot    = "sentinelforge.events.v1"
	alertStreamName     = "SENTINELFORGE_ALERTS"
	alertSubjectRoot    = "sentinelforge.alerts.v1"
	incidentStreamName  = "SENTINELFORGE_INCIDENTS"
	incidentSubjectRoot = "sentinelforge.incidents.v1"
)

// JetStreamPublisher publishes validated events to a durable NATS stream.
type JetStreamPublisher struct {
	js nats.JetStreamContext
}

func Connect(url string) (*JetStreamPublisher, *nats.Conn, error) {
	options := []nats.Option{
		nats.Name("sentinelforge-gateway"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	}
	if os.Getenv("SF_MTLS_REQUIRED") == "true" {
		caFile, certFile, keyFile := os.Getenv("SF_NATS_CA_FILE"), os.Getenv("SF_NATS_CERT_FILE"), os.Getenv("SF_NATS_KEY_FILE")
		if caFile == "" || certFile == "" || keyFile == "" {
			return nil, nil, fmt.Errorf("SF_MTLS_REQUIRED needs SF_NATS_CA_FILE, SF_NATS_CERT_FILE, and SF_NATS_KEY_FILE")
		}
		options = append(options, nats.RootCAs(caFile), nats.ClientCert(certFile, keyFile))
		if strings.HasPrefix(url, "nats://") {
			url = "tls://" + strings.TrimPrefix(url, "nats://")
		}
		if !strings.HasPrefix(url, "tls://") {
			return nil, nil, fmt.Errorf("mutual TLS requires a tls:// NATS URL")
		}
	}
	conn, err := nats.Connect(url, options...)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to NATS: %w", err)
	}

	js, err := conn.JetStream()
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("initialize JetStream client: %w", err)
	}
	streams := []nats.StreamConfig{
		{
			Name:      eventStreamName,
			Subjects:  []string{eventSubjectRoot + ".>"},
			Retention: nats.LimitsPolicy,
			Storage:   nats.FileStorage,
		},
		{
			Name:      alertStreamName,
			Subjects:  []string{alertSubjectRoot + ".>"},
			Retention: nats.LimitsPolicy,
			Storage:   nats.FileStorage,
		},
		{
			Name:      incidentStreamName,
			Subjects:  []string{incidentSubjectRoot + ".>"},
			Retention: nats.LimitsPolicy,
			Storage:   nats.FileStorage,
		},
	}
	for _, config := range streams {
		if _, err := js.StreamInfo(config.Name); errors.Is(err, nats.ErrStreamNotFound) {
			if _, addErr := js.AddStream(&config); addErr != nil {
				conn.Close()
				return nil, nil, fmt.Errorf("ensure JetStream stream %s: %w", config.Name, addErr)
			}
		} else if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("inspect JetStream stream %s: %w", config.Name, err)
		}
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
	if _, err := p.js.Publish(eventSubjectRoot+"."+event.Category, body, nats.Context(ctx)); err != nil {
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
	return p.ConsumeSubject(ctx, eventSubjectRoot+".>", durableName, handler)
}

// ConsumeSubject delivers a durable subject to handler. Messages are
// acknowledged only after handler succeeds; failures are retried after a delay.
func (p *JetStreamPublisher) ConsumeSubject(
	ctx context.Context,
	subject string,
	durableName string,
	handler func(context.Context, []byte) error,
) error {
	subscription, err := p.js.PullSubscribe(
		subject,
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
					return fmt.Errorf("reject failed message write: %w (handler error: %v)", nakErr, err)
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
