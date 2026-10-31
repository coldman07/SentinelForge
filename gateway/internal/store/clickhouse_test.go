package store

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetAlertUsesBoundEventIDAndReturnsEvidence(t *testing.T) {
	const evidence = `{"event_id":"event-1","matches":[]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("param_event_id"); got != "event-1' OR 1=1" {
			t.Errorf("param_event_id = %q, want event ID unchanged", got)
		}
		query := r.URL.Query().Get("query")
		if !strings.Contains(query, "event_id = {event_id:String}") {
			t.Errorf("query does not use a ClickHouse parameter: %s", query)
		}
		if strings.Contains(query, "OR 1=1") {
			t.Errorf("event ID was interpolated into SQL: %s", query)
		}
		encoded, err := json.Marshal(alertEvidenceRow{AlertJSON: json.RawMessage(evidence)})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(encoded)
	}))
	defer server.Close()

	store, err := NewClickHouseStore(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.GetAlert(context.Background(), "event-1' OR 1=1")
	if err != nil {
		t.Fatalf("GetAlert() error = %v", err)
	}
	if string(got) != evidence {
		t.Fatalf("GetAlert() = %s, want %s", got, evidence)
	}
}

func TestGetAlertReturnsNilWhenNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer server.Close()

	store, err := NewClickHouseStore(server.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.GetAlert(context.Background(), "missing")
	if err != nil {
		t.Fatalf("GetAlert() error = %v", err)
	}
	if got != nil {
		t.Fatalf("GetAlert() = %s, want nil", got)
	}
}
