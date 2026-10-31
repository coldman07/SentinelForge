package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const schema = `CREATE TABLE IF NOT EXISTS sentinelforge.events
(
	 event_id String,
	 timestamp DateTime64(9, 'UTC'),
	 host_id String,
	 category LowCardinality(String),
	 action LowCardinality(String),
	 event_json String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (host_id, category, timestamp, event_id)`

// ClickHouseStore writes normalized events using ClickHouse's HTTP interface.
type ClickHouseStore struct {
	endpoint *url.URL
	username string
	password string
	client   *http.Client
}

type eventRow struct {
	EventID   string `json:"event_id"`
	Timestamp string `json:"timestamp"`
	Host      struct {
		HostID string `json:"host_id"`
	} `json:"host"`
	Category  string `json:"category"`
	Action    string `json:"action"`
	EventJSON string `json:"event_json"`
}

func NewClickHouseStore(endpoint, username, password string) (*ClickHouseStore, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid ClickHouse endpoint %q", endpoint)
	}
	return &ClickHouseStore{
		endpoint: parsed,
		username: username,
		password: password,
		client:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (s *ClickHouseStore) EnsureSchema(ctx context.Context) error {
	if err := s.query(ctx, "CREATE DATABASE IF NOT EXISTS sentinelforge"); err != nil {
		return fmt.Errorf("create event database: %w", err)
	}
	if err := s.query(ctx, schema); err != nil {
		return fmt.Errorf("create events table: %w", err)
	}
	return nil
}

// InsertEvent stores searchable envelope columns and preserves the full event
// JSON for fields not yet promoted into the event table schema.
func (s *ClickHouseStore) InsertEvent(ctx context.Context, event []byte) error {
	var row eventRow
	if err := json.Unmarshal(event, &row); err != nil {
		return fmt.Errorf("decode event envelope: %w", err)
	}
	if row.EventID == "" || row.Timestamp == "" || row.Host.HostID == "" || row.Category == "" || row.Action == "" {
		return fmt.Errorf("event is missing one or more required store columns")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, row.Timestamp)
	if err != nil {
		return fmt.Errorf("parse event timestamp: %w", err)
	}
	row.Timestamp = timestamp.UTC().Format("2006-01-02 15:04:05.999999999")
	row.EventJSON = string(event)

	body, err := json.Marshal(row)
	if err != nil {
		return fmt.Errorf("encode ClickHouse row: %w", err)
	}
	return s.request(ctx, "INSERT INTO sentinelforge.events FORMAT JSONEachRow", bytes.NewReader(body))
}

func (s *ClickHouseStore) query(ctx context.Context, query string) error {
	return s.request(ctx, query, strings.NewReader(""))
}

func (s *ClickHouseStore) request(ctx context.Context, query string, body io.Reader) error {
	endpoint := *s.endpoint
	parameters := endpoint.Query()
	parameters.Set("query", query)
	endpoint.RawQuery = parameters.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), body)
	if err != nil {
		return fmt.Errorf("build ClickHouse request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if s.username != "" {
		request.SetBasicAuth(s.username, s.password)
	}

	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("send ClickHouse request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("ClickHouse returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	return nil
}
