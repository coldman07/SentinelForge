package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

type recordingPublisher struct {
	event Event
	err   error
	calls int
}

type recordingAlertReader struct {
	alerts []json.RawMessage
	alert  json.RawMessage
	err    error
	limit  int
	calls  int
	id     string
}

func (r *recordingAlertReader) ListAlerts(_ context.Context, limit int) ([]json.RawMessage, error) {
	r.limit = limit
	r.calls++
	return r.alerts, r.err
}

func (r *recordingAlertReader) GetAlert(_ context.Context, eventID string) (json.RawMessage, error) {
	r.id = eventID
	r.calls++
	return r.alert, r.err
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

func TestDashboardServesEmbeddedPage(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	NewHandler(nil).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", response.Header().Get("Content-Type"))
	}
	if !strings.Contains(response.Body.String(), "SentinelForge") {
		t.Fatal("dashboard page does not contain its title")
	}
	assetPath := regexp.MustCompile(`src="([^"]+\.js)"`).FindStringSubmatch(response.Body.String())
	if len(assetPath) != 2 {
		t.Fatal("dashboard page does not reference its JavaScript bundle")
	}
	assetRequest := httptest.NewRequest(http.MethodGet, assetPath[1], nil)
	assetResponse := httptest.NewRecorder()
	NewHandler(nil).ServeHTTP(assetResponse, assetRequest)
	if assetResponse.Code != http.StatusOK {
		t.Fatalf("JavaScript bundle status = %d, want %d", assetResponse.Code, http.StatusOK)
	}
	if !strings.Contains(assetResponse.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("JavaScript bundle Content-Type = %q", assetResponse.Header().Get("Content-Type"))
	}
}

func TestAlertsAreLoopbackOnly(t *testing.T) {
	reader := &recordingAlertReader{}
	request := httptest.NewRequest(http.MethodGet, "/v1/alerts", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	response := httptest.NewRecorder()

	NewHandlerWithAlerts(nil, reader).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if reader.calls != 0 {
		t.Fatalf("alert reader calls = %d, want 0", reader.calls)
	}
}

func TestAlertsEndpointCapsLimitAndReturnsNoStore(t *testing.T) {
	reader := &recordingAlertReader{alerts: []json.RawMessage{json.RawMessage(`{"event_id":"event-1"}`)}}
	request := httptest.NewRequest(http.MethodGet, "/v1/alerts?limit=500", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()

	NewHandlerWithAlerts(nil, reader).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if reader.limit != 100 {
		t.Fatalf("reader limit = %d, want 100", reader.limit)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	if !strings.Contains(response.Body.String(), `"event_id":"event-1"`) {
		t.Fatalf("response does not contain alert record: %s", response.Body.String())
	}
}

func TestAlertEvidenceIsLoopbackOnly(t *testing.T) {
	reader := &recordingAlertReader{alert: json.RawMessage(`{"event_id":"event-1"}`)}
	request := httptest.NewRequest(http.MethodGet, "/v1/alerts/event-1", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	response := httptest.NewRecorder()

	NewHandlerWithAlerts(nil, reader).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if reader.calls != 0 {
		t.Fatalf("alert reader calls = %d, want 0", reader.calls)
	}
}

func TestAlertEvidenceReturnsStoredRecord(t *testing.T) {
	reader := &recordingAlertReader{alert: json.RawMessage(`{"event_id":"event-1","matches":[]}`)}
	request := httptest.NewRequest(http.MethodGet, "/v1/alerts/event-1", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()

	NewHandlerWithAlerts(nil, reader).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if reader.id != "event-1" {
		t.Fatalf("requested event ID = %q, want event-1", reader.id)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	if !strings.Contains(response.Body.String(), `"matches":[]`) {
		t.Fatalf("response does not contain evidence: %s", response.Body.String())
	}
}

func TestAlertEvidenceReturnsNotFoundWhenMissing(t *testing.T) {
	reader := &recordingAlertReader{}
	request := httptest.NewRequest(http.MethodGet, "/v1/alerts/missing", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()

	NewHandlerWithAlerts(nil, reader).ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}
