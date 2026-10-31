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

const alertSchema = `CREATE TABLE IF NOT EXISTS sentinelforge.alerts
(
	 event_id String,
	 timestamp DateTime64(9, 'UTC'),
	 host_id String,
	 match_count UInt32,
	 rule_ids Array(String),
	 rule_titles Array(String),
	 levels Array(String),
	 alert_json String
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (host_id, timestamp, event_id)`

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

type alertEnvelope struct {
	EventID string `json:"event_id"`
	Event   struct {
		EventID   string `json:"event_id"`
		Timestamp string `json:"timestamp"`
		Host      struct {
			HostID string `json:"host_id"`
		} `json:"host"`
	} `json:"event"`
	Matches []struct {
		RuleID string `json:"rule_id"`
		Title  string `json:"title"`
		Level  string `json:"level"`
	} `json:"matches"`
}

type alertRow struct {
	EventID    string   `json:"event_id"`
	Timestamp  string   `json:"timestamp"`
	HostID     string   `json:"host_id"`
	MatchCount uint32   `json:"match_count"`
	RuleIDs    []string `json:"rule_ids"`
	RuleTitles []string `json:"rule_titles"`
	Levels     []string `json:"levels"`
	AlertJSON  string   `json:"alert_json"`
}

type alertSummaryRow struct {
	EventID    string   `json:"event_id"`
	Timestamp  string   `json:"timestamp"`
	HostID     string   `json:"host_id"`
	MatchCount uint32   `json:"match_count"`
	RuleIDs    []string `json:"rule_ids"`
	RuleTitles []string `json:"rule_titles"`
	Levels     []string `json:"levels"`
}

type alertEvidenceRow struct {
	AlertJSON json.RawMessage `json:"alert_json"`
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
	if err := s.query(ctx, alertSchema); err != nil {
		return fmt.Errorf("create alerts table: %w", err)
	}
	if err := s.query(ctx, "ALTER TABLE sentinelforge.alerts ADD COLUMN IF NOT EXISTS rule_titles Array(String) AFTER rule_ids"); err != nil {
		return fmt.Errorf("add alert rule titles column: %w", err)
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

// InsertAlert stores a detection result with searchable envelope fields and
// retains the matched event and rule metadata as JSON evidence.
func (s *ClickHouseStore) InsertAlert(ctx context.Context, alert []byte) error {
	var envelope alertEnvelope
	if err := json.Unmarshal(alert, &envelope); err != nil {
		return fmt.Errorf("decode alert envelope: %w", err)
	}
	if envelope.EventID == "" || envelope.Event.Timestamp == "" || envelope.Event.Host.HostID == "" || len(envelope.Matches) == 0 {
		return fmt.Errorf("alert is missing one or more required store fields")
	}
	if envelope.Event.EventID != envelope.EventID {
		return fmt.Errorf("alert event_id does not match its evidence event")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, envelope.Event.Timestamp)
	if err != nil {
		return fmt.Errorf("parse alert event timestamp: %w", err)
	}

	row := alertRow{
		EventID:    envelope.EventID,
		Timestamp:  timestamp.UTC().Format("2006-01-02 15:04:05.999999999"),
		HostID:     envelope.Event.Host.HostID,
		MatchCount: uint32(len(envelope.Matches)),
		RuleIDs:    []string{},
		RuleTitles: []string{},
		Levels:     []string{},
		AlertJSON:  string(alert),
	}
	for _, match := range envelope.Matches {
		row.RuleIDs = append(row.RuleIDs, match.RuleID)
		row.RuleTitles = append(row.RuleTitles, match.Title)
		row.Levels = append(row.Levels, match.Level)
	}
	body, err := json.Marshal(row)
	if err != nil {
		return fmt.Errorf("encode ClickHouse alert row: %w", err)
	}
	return s.request(ctx, "INSERT INTO sentinelforge.alerts FORMAT JSONEachRow", bytes.NewReader(body))
}

// ListAlerts returns the newest alert summaries for the local dashboard.
func (s *ClickHouseStore) ListAlerts(ctx context.Context, limit int) ([]json.RawMessage, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	query := fmt.Sprintf(`SELECT
	 event_id,
	 formatDateTime(timestamp, '%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ', 'UTC') AS timestamp,
	 host_id,
	 match_count,
	 rule_ids,
	 rule_titles,
	 levels
FROM sentinelforge.alerts
ORDER BY timestamp DESC
LIMIT %d
FORMAT JSONEachRow`, limit)
	body, err := s.requestBody(ctx, query, strings.NewReader(""))
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	alerts := make([]json.RawMessage, 0, limit)
	for {
		var alert alertSummaryRow
		if err := decoder.Decode(&alert); err != nil {
			if err == io.EOF {
				return alerts, nil
			}
			return nil, fmt.Errorf("decode ClickHouse alert summary: %w", err)
		}
		encoded, err := json.Marshal(alert)
		if err != nil {
			return nil, fmt.Errorf("encode alert summary: %w", err)
		}
		alerts = append(alerts, encoded)
	}
}

// GetAlert returns the full stored alert and event evidence for investigation.
func (s *ClickHouseStore) GetAlert(ctx context.Context, eventID string) (json.RawMessage, error) {
	query := `SELECT alert_json
FROM sentinelforge.alerts
WHERE event_id = {event_id:String}
ORDER BY timestamp DESC
LIMIT 1
FORMAT JSONEachRow`
	parameters := url.Values{"param_event_id": []string{eventID}}
	body, err := s.requestBodyWithParams(ctx, query, strings.NewReader(""), parameters)
	if err != nil {
		return nil, err
	}
	var row alertEvidenceRow
	if err := json.Unmarshal(body, &row); err != nil {
		if len(body) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("decode ClickHouse alert evidence: %w", err)
	}
	if !json.Valid(row.AlertJSON) {
		return nil, fmt.Errorf("ClickHouse returned invalid alert evidence JSON")
	}
	return row.AlertJSON, nil
}

func (s *ClickHouseStore) query(ctx context.Context, query string) error {
	return s.request(ctx, query, strings.NewReader(""))
}

func (s *ClickHouseStore) request(ctx context.Context, query string, body io.Reader) error {
	_, err := s.requestBody(ctx, query, body)
	return err
}

func (s *ClickHouseStore) requestBody(ctx context.Context, query string, body io.Reader) ([]byte, error) {
	return s.requestBodyWithParams(ctx, query, body, nil)
}

func (s *ClickHouseStore) requestBodyWithParams(ctx context.Context, query string, body io.Reader, extra url.Values) ([]byte, error) {
	endpoint := *s.endpoint
	parameters := endpoint.Query()
	parameters.Set("query", query)
	for key, values := range extra {
		for _, value := range values {
			parameters.Add(key, value)
		}
	}
	endpoint.RawQuery = parameters.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), body)
	if err != nil {
		return nil, fmt.Errorf("build ClickHouse request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if s.username != "" {
		request.SetBasicAuth(s.username, s.password)
	}

	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("send ClickHouse request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("ClickHouse returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	result, err := io.ReadAll(io.LimitReader(response.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("read ClickHouse response: %w", err)
	}
	return result, nil
}
