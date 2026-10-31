package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/coldman07/SentinelForge/gateway/internal/dashboard"
	"github.com/coldman07/SentinelForge/gateway/internal/store"
)

const maxEventBytes = 1 << 20

// Publisher is implemented by the event-bus integration. Publish must return
// only after it has accepted responsibility for the event.
type Publisher interface {
	Publish(event Event) error
}

// EventReader provides recent stored events to the local dashboard.
type EventReader interface {
	ListRecentEvents(ctx context.Context, limit int) ([]store.EventSummary, error)
}

// AlertReader provides recent stored detections to the local dashboard.
type AlertReader interface {
	ListRecentAlerts(ctx context.Context, limit int) ([]store.AlertSummary, error)
}

// Event is the JSON representation of sentinelforge.events.v1.Event. The
// protobuf contract remains authoritative for the eventual gRPC transport.
type Event struct {
	EventID        string          `json:"event_id"`
	Timestamp      string          `json:"timestamp"`
	Host           Host            `json:"host"`
	Category       string          `json:"category"`
	Action         string          `json:"action"`
	SchemaVersion  string          `json:"schema_version"`
	CorrelationID  string          `json:"correlation_id,omitempty"`
	User           User            `json:"user,omitempty"`
	Raw            RawSource       `json:"raw,omitempty"`
	Process        json.RawMessage `json:"process,omitempty"`
	Authentication json.RawMessage `json:"authentication,omitempty"`
	File           json.RawMessage `json:"file,omitempty"`
	Service        json.RawMessage `json:"service,omitempty"`
	Persistence    json.RawMessage `json:"persistence,omitempty"`
	Network        json.RawMessage `json:"network,omitempty"`
}

type Host struct {
	HostID       string `json:"host_id"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
}

type User struct {
	Name      string `json:"name"`
	SID       string `json:"sid"`
	Privilege string `json:"privilege"`
}

type RawSource struct {
	Source   string `json:"source"`
	Provider string `json:"provider"`
}

type Handler struct {
	publisher   Publisher
	eventReader EventReader
	alertReader AlertReader
}

func NewHandler(publisher Publisher) http.Handler {
	return NewHandlerWithData(publisher, nil, nil)
}

func NewHandlerWithEvents(publisher Publisher, eventReader EventReader) http.Handler {
	return NewHandlerWithData(publisher, eventReader, nil)
}

func NewHandlerWithData(publisher Publisher, eventReader EventReader, alertReader AlertReader) http.Handler {
	h := &Handler{publisher: publisher, eventReader: eventReader, alertReader: alertReader}
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", dashboard.Handler())
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /v1/events", h.events)
	mux.HandleFunc("GET /v1/alerts", h.alerts)
	mux.HandleFunc("POST /v1/events", h.ingest)
	return mux
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) events(w http.ResponseWriter, r *http.Request) {
	if !h.requireLoopback(w, r) {
		return
	}
	if h.eventReader == nil {
		http.Error(w, "event store is not configured", http.StatusServiceUnavailable)
		return
	}
	limit, ok := requestedLimit(w, r)
	if !ok {
		return
	}
	events, err := h.eventReader.ListRecentEvents(r.Context(), limit)
	if err != nil {
		http.Error(w, "could not load event records", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(events); err != nil {
		return
	}
}

func (h *Handler) alerts(w http.ResponseWriter, r *http.Request) {
	if !h.requireLoopback(w, r) {
		return
	}
	if h.alertReader == nil {
		http.Error(w, "alert store is not configured", http.StatusServiceUnavailable)
		return
	}
	limit, ok := requestedLimit(w, r)
	if !ok {
		return
	}
	alerts, err := h.alertReader.ListRecentAlerts(r.Context(), limit)
	if err != nil {
		http.Error(w, "could not load alert records", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(alerts); err != nil {
		return
	}
}

func (h *Handler) requireLoopback(w http.ResponseWriter, r *http.Request) bool {
	if isLoopbackRequest(r) {
		return true
	}
	http.Error(w, "dashboard data is available from this machine only", http.StatusForbidden)
	return false
}

func requestedLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	limit := 100
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed < 1 {
			http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
			return 0, false
		}
		if parsed < limit {
			limit = parsed
		}
	}
	return limit, true
}

func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = strings.Trim(r.RemoteAddr, "[]")
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func (h *Handler) ingest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxEventBytes)
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var event Event
	if err := decoder.Decode(&event); err != nil {
		http.Error(w, "invalid event JSON", http.StatusBadRequest)
		return
	}
	if err := ensureSingleJSONValue(decoder); err != nil {
		http.Error(w, "request must contain one event", http.StatusBadRequest)
		return
	}
	if err := event.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if h.publisher == nil {
		http.Error(w, "event publisher is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := h.publisher.Publish(event); err != nil {
		http.Error(w, "event could not be accepted", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func ensureSingleJSONValue(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}
