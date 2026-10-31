package ingest

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const maxEventBytes = 1 << 20

// Publisher is implemented by the event-bus integration. Publish must return
// only after it has accepted responsibility for the event.
type Publisher interface {
	Publish(event Event) error
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
	publisher Publisher
}

func NewHandler(publisher Publisher) http.Handler {
	h := &Handler{publisher: publisher}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("POST /v1/events", h.ingest)
	return mux
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
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
