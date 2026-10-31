package ingest

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type recordingPublisher struct {
	event Event
	err   error
	calls int
}

func (p *recordingPublisher) Publish(event Event) error {
	p.event = event
	p.calls++
	return p.err
}

const validProcessEvent = `{
  "event_id": "b6f1c9e2-3a4d-4c1e-9f0a-7e5d2c1b8a90",
  "timestamp": "2026-01-15T10:42:07.318Z",
  "host": {"host_id":"win-lab-01","os":"windows","os_version":"10.0.19045","agent_version":"0.1.0"},
  "category": "process",
  "action": "create",
  "user": {"name":"labuser","sid":"S-1-5-21-test","privilege":"standard"},
  "process": {"pid":4312,"name":"powershell.exe","path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
  "raw": {"source":"ETW","provider":"Microsoft-Windows-Kernel-Process"},
  "schema_version": "1.0"
}`

func TestIngestPublishesDocumentedEvent(t *testing.T) {
	publisher := &recordingPublisher{}
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(validProcessEvent))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	NewHandler(publisher).ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body: %s", response.Code, http.StatusAccepted, response.Body.String())
	}
	if publisher.calls != 1 {
		t.Fatalf("publish calls = %d, want 1", publisher.calls)
	}
	if publisher.event.User.Name != "labuser" || publisher.event.Raw.Source != "ETW" {
		t.Fatalf("user/raw fields were not forwarded: user=%+v raw=%+v", publisher.event.User, publisher.event.Raw)
	}
	if string(publisher.event.Process) == "" {
		t.Fatal("process details were not forwarded")
	}
}

func TestIngestPreservesRenameCorrelationID(t *testing.T) {
	correlationID := "a1b2c3d4e5f60718"
	body := strings.Replace(
		validProcessEvent,
		`"schema_version": "1.0"`,
		`"schema_version": "1.0", "correlation_id": "`+correlationID+`"`,
		1,
	)
	publisher := &recordingPublisher{}
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	NewHandler(publisher).ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body: %s", response.Code, http.StatusAccepted, response.Body.String())
	}
	if publisher.event.CorrelationID != correlationID {
		t.Fatalf("correlation_id = %q, want %q", publisher.event.CorrelationID, correlationID)
	}
}

func TestIngestRejectsMismatchedDetails(t *testing.T) {
	publisher := &recordingPublisher{}
	body := strings.Replace(validProcessEvent, `"category": "process"`, `"category": "file"`, 1)
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	NewHandler(publisher).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if publisher.calls != 0 {
		t.Fatalf("publish calls = %d, want 0", publisher.calls)
	}
}

func TestIngestReturnsUnavailableWhenPublishFails(t *testing.T) {
	publisher := &recordingPublisher{err: errors.New("bus unavailable")}
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(validProcessEvent))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	NewHandler(publisher).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if publisher.calls != 1 {
		t.Fatalf("publish calls = %d, want 1", publisher.calls)
	}
}

func TestHealthReturnsNoContent(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()

	NewHandler(nil).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}
