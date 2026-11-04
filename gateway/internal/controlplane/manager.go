// Package controlplane implements SentinelForge's local rule and response approval APIs.
package controlplane

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxRuleBytes       = 512 << 10
	maxReplayBodyBytes = 2 << 20
	maxRequestBytes    = 64 << 10
)

type Actor struct {
	ID   string `json:"id"`
	Role string `json:"role"`
}

type tokenRecord struct {
	Actor
}

type Candidate struct {
	ID              string         `json:"candidate_id"`
	RuleID          string         `json:"rule_id"`
	Title           string         `json:"title"`
	RuleYAML        string         `json:"rule_yaml"`
	Status          string         `json:"status"`
	CreatedBy       Actor          `json:"created_by"`
	CreatedAt       time.Time      `json:"created_at"`
	Validation      map[string]any `json:"validation"`
	Replay          map[string]any `json:"replay,omitempty"`
	ApprovedVersion int            `json:"approved_version,omitempty"`
}

type RuleVersion struct {
	RuleID     string    `json:"rule_id"`
	Version    int       `json:"version"`
	Title      string    `json:"title"`
	RuleYAML   string    `json:"rule_yaml"`
	SHA256     string    `json:"sha256"`
	Signature  string    `json:"signature"`
	SignedBy   Actor     `json:"signed_by"`
	SignedAt   time.Time `json:"signed_at"`
	Candidate  string    `json:"candidate_id,omitempty"`
	RollbackOf int       `json:"rollback_of,omitempty"`
}

type ResponseApproval struct {
	Approver Actor     `json:"approver"`
	At       time.Time `json:"at"`
}

type ResponseRequest struct {
	ID            string            `json:"request_id"`
	Action        string            `json:"action"`
	Target        string            `json:"target"`
	Justification string            `json:"justification"`
	Requester     Actor             `json:"requester"`
	RequestedAt   time.Time         `json:"requested_at"`
	Status        string            `json:"status"`
	Decision      map[string]any    `json:"policy_decision"`
	Approval      *ResponseApproval `json:"approval,omitempty"`
}

type AuditEntry struct {
	Sequence uint64         `json:"sequence"`
	At       time.Time      `json:"at"`
	Actor    Actor          `json:"actor"`
	Action   string         `json:"action"`
	Resource string         `json:"resource"`
	Details  map[string]any `json:"details,omitempty"`
	Previous string         `json:"previous_hash"`
	Hash     string         `json:"hash"`
}

type controlState struct {
	Candidates map[string]Candidate       `json:"candidates"`
	Versions   map[string][]RuleVersion   `json:"versions"`
	Requests   map[string]ResponseRequest `json:"response_requests"`
	Audit      []AuditEntry               `json:"audit"`
}

type Manager struct {
	mu         sync.RWMutex
	state      controlState
	statePath  string
	validator  string
	opaURL     string
	signingKey []byte
	tokens     map[string]tokenRecord
	client     *http.Client
	loadErr    error
}

func NewFromEnv() *Manager {
	statePath := envOr("SF_CONTROL_STATE_PATH", "data/control-plane.json")
	validator := envOr("SF_DETECTION_BIN", "sentinelforge-detection")
	if _, err := exec.LookPath(validator); err != nil && os.Getenv("SF_DETECTION_BIN") == "" {
		if _, windowsErr := exec.LookPath(validator + ".exe"); windowsErr == nil {
			validator += ".exe"
		}
	}
	manager := &Manager{
		state:      newState(),
		statePath:  statePath,
		validator:  validator,
		opaURL:     strings.TrimRight(envOr("SF_OPA_URL", "http://127.0.0.1:8181"), "/"),
		signingKey: []byte(os.Getenv("SF_RULE_SIGNING_KEY")),
		tokens:     loadTokens(os.Getenv("SF_CONTROL_TOKENS_JSON")),
		client:     &http.Client{Timeout: 5 * time.Second},
	}
	manager.loadErr = manager.load()
	return manager
}

func (m *Manager) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/rules", m.listRules)
	mux.HandleFunc("POST /v1/rules/candidates", m.createCandidate)
	mux.HandleFunc("POST /v1/rules/candidates/{candidateID}/replay", m.replayCandidate)
	mux.HandleFunc("POST /v1/rules/candidates/{candidateID}/approve", m.approveCandidate)
	mux.HandleFunc("GET /v1/rules/{ruleID}/versions", m.listVersions)
	mux.HandleFunc("GET /v1/rules/{ruleID}/versions/{version}", m.getVersion)
	mux.HandleFunc("POST /v1/rules/{ruleID}/rollback", m.rollbackRule)
	mux.HandleFunc("GET /v1/response-requests", m.listResponseRequests)
	mux.HandleFunc("POST /v1/response-requests", m.createResponseRequest)
	mux.HandleFunc("POST /v1/response-requests/{requestID}/approve", m.approveResponseRequest)
	mux.HandleFunc("POST /v1/response-requests/{requestID}/reject", m.rejectResponseRequest)
	mux.HandleFunc("GET /v1/audit", m.listAudit)
	mux.HandleFunc("GET /v1/audit/verify", m.verifyAudit)
}

func (m *Manager) createCandidate(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.authorize(w, r, "analyst", "approver", "admin")
	if !ok {
		return
	}
	var request struct {
		RuleYAML string `json:"rule_yaml"`
	}
	if !decodeJSON(w, r, maxRuleBytes, &request) {
		return
	}
	if strings.TrimSpace(request.RuleYAML) == "" || len(request.RuleYAML) > maxRuleBytes {
		http.Error(w, "rule_yaml must be between 1 byte and 512 KiB", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var metadata map[string]any
	if err := m.runValidator(ctx, "--validate-rule", []byte(request.RuleYAML), &metadata); err != nil {
		http.Error(w, "Sigma validation failed: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	id, err := randomID("CAND-")
	if err != nil {
		http.Error(w, "could not allocate candidate ID", http.StatusInternalServerError)
		return
	}
	ruleID, _ := metadata["rule_id"].(string)
	if strings.TrimSpace(ruleID) == "" {
		http.Error(w, "Sigma candidate must define a stable id", http.StatusUnprocessableEntity)
		return
	}
	title, _ := metadata["title"].(string)
	candidate := Candidate{
		ID: id, RuleID: ruleID, Title: title, RuleYAML: request.RuleYAML,
		Status: "validated", CreatedBy: actor, CreatedAt: time.Now().UTC(), Validation: metadata,
	}
	err = m.update(actor, "candidate.create", id, map[string]any{"rule_id": ruleID, "title": title}, func(state *controlState) error {
		state.Candidates[id] = candidate
		return nil
	})
	if err != nil {
		http.Error(w, "could not persist candidate", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, candidate)
}

func (m *Manager) replayCandidate(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.authorize(w, r, "analyst", "approver", "admin")
	if !ok {
		return
	}
	var request struct {
		PositiveEvents []json.RawMessage `json:"positive_events"`
		NegativeEvents []json.RawMessage `json:"negative_events"`
	}
	if !decodeJSON(w, r, maxReplayBodyBytes, &request) {
		return
	}
	if len(request.PositiveEvents) == 0 || len(request.NegativeEvents) == 0 || len(request.PositiveEvents) > 500 || len(request.NegativeEvents) > 500 {
		http.Error(w, "provide 1-500 positive and 1-500 benign events", http.StatusBadRequest)
		return
	}
	candidateID := r.PathValue("candidateID")
	m.mu.RLock()
	candidate, exists := m.state.Candidates[candidateID]
	m.mu.RUnlock()
	if !exists {
		http.NotFound(w, r)
		return
	}
	if candidate.Status != "validated" && candidate.Status != "replay_failed" {
		http.Error(w, "candidate is not eligible for replay", http.StatusConflict)
		return
	}
	input, _ := json.Marshal(map[string]any{
		"rule_yaml":       candidate.RuleYAML,
		"positive_events": request.PositiveEvents,
		"negative_events": request.NegativeEvents,
	})
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var result map[string]any
	if err := m.runValidator(ctx, "--replay-rule", input, &result); err != nil {
		http.Error(w, "Sigma replay failed: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	passed, _ := result["passed"].(bool)
	candidate.Replay = result
	if passed {
		candidate.Status = "tested"
	} else {
		candidate.Status = "replay_failed"
	}
	err := m.update(actor, "candidate.replay", candidateID, result, func(state *controlState) error {
		current, found := state.Candidates[candidateID]
		if !found || (current.Status != "validated" && current.Status != "replay_failed") {
			return errors.New("candidate changed during replay")
		}
		state.Candidates[candidateID] = candidate
		return nil
	})
	if err != nil {
		http.Error(w, "could not persist replay result: "+err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, candidate)
}

func (m *Manager) approveCandidate(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.authorize(w, r, "approver", "admin")
	if !ok {
		return
	}
	if len(m.signingKey) < 32 {
		http.Error(w, "rule approval is disabled: SF_RULE_SIGNING_KEY must contain at least 32 bytes", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("candidateID")
	m.mu.RLock()
	candidate, exists := m.state.Candidates[id]
	versionNumber := len(m.state.Versions[candidate.RuleID]) + 1
	m.mu.RUnlock()
	if !exists {
		http.NotFound(w, r)
		return
	}
	if candidate.Status != "tested" || candidate.Replay == nil {
		http.Error(w, "candidate must pass positive and benign replay before approval", http.StatusConflict)
		return
	}
	if candidate.CreatedBy.ID == actor.ID {
		http.Error(w, "candidate authors cannot approve their own rules", http.StatusForbidden)
		return
	}
	version := m.signVersion(candidate.RuleID, versionNumber, candidate.Title, candidate.RuleYAML, actor, id, 0)
	err := m.update(actor, "candidate.approve", id, map[string]any{"rule_id": candidate.RuleID, "version": versionNumber, "sha256": version.SHA256}, func(state *controlState) error {
		current, found := state.Candidates[id]
		if !found || current.Status != "tested" || len(state.Versions[current.RuleID])+1 != versionNumber {
			return errors.New("candidate or version changed during approval")
		}
		state.Versions[current.RuleID] = append(state.Versions[current.RuleID], version)
		current.Status = "approved"
		current.ApprovedVersion = versionNumber
		state.Candidates[id] = current
		return nil
	})
	if err != nil {
		http.Error(w, "could not approve candidate: "+err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusCreated, version)
}

func (m *Manager) listRules(w http.ResponseWriter, r *http.Request) {
	if !loopbackRequest(r) {
		http.Error(w, "control-plane API is available from this machine only", http.StatusForbidden)
		return
	}
	if !m.ready(w) {
		return
	}
	m.mu.RLock()
	candidates := make([]Candidate, 0, len(m.state.Candidates))
	for _, candidate := range m.state.Candidates {
		candidates = append(candidates, candidate)
	}
	m.mu.RUnlock()
	writeJSON(w, http.StatusOK, candidates)
}

func (m *Manager) listVersions(w http.ResponseWriter, r *http.Request) {
	if !m.readAccess(w, r) {
		return
	}
	m.mu.RLock()
	versions := append([]RuleVersion(nil), m.state.Versions[r.PathValue("ruleID")]...)
	m.mu.RUnlock()
	writeJSON(w, http.StatusOK, versions)
}

func (m *Manager) getVersion(w http.ResponseWriter, r *http.Request) {
	if !m.readAccess(w, r) {
		return
	}
	versionNumber, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || versionNumber < 1 {
		http.Error(w, "version must be a positive integer", http.StatusBadRequest)
		return
	}
	m.mu.RLock()
	versions := m.state.Versions[r.PathValue("ruleID")]
	var found *RuleVersion
	for i := range versions {
		if versions[i].Version == versionNumber {
			copy := versions[i]
			found = &copy
			break
		}
	}
	m.mu.RUnlock()
	if found == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, found)
}

func (m *Manager) rollbackRule(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.authorize(w, r, "approver", "admin")
	if !ok {
		return
	}
	if len(m.signingKey) < 32 {
		http.Error(w, "rollback is disabled: SF_RULE_SIGNING_KEY must contain at least 32 bytes", http.StatusServiceUnavailable)
		return
	}
	var request struct {
		Version int `json:"version"`
	}
	if !decodeJSON(w, r, maxRequestBytes, &request) {
		return
	}
	ruleID := r.PathValue("ruleID")
	m.mu.RLock()
	versions := append([]RuleVersion(nil), m.state.Versions[ruleID]...)
	m.mu.RUnlock()
	var source *RuleVersion
	for i := range versions {
		if versions[i].Version == request.Version {
			copy := versions[i]
			source = &copy
			break
		}
	}
	if source == nil {
		http.NotFound(w, r)
		return
	}
	nextVersion := len(versions) + 1
	version := m.signVersion(ruleID, nextVersion, source.Title, source.RuleYAML, actor, "", source.Version)
	err := m.update(actor, "rule.rollback", ruleID, map[string]any{"from_version": source.Version, "version": nextVersion, "sha256": version.SHA256}, func(state *controlState) error {
		if len(state.Versions[ruleID])+1 != nextVersion {
			return errors.New("rule versions changed during rollback")
		}
		state.Versions[ruleID] = append(state.Versions[ruleID], version)
		return nil
	})
	if err != nil {
		http.Error(w, "could not record rollback: "+err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusCreated, version)
}

func (m *Manager) createResponseRequest(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.authorize(w, r, "analyst", "approver", "admin")
	if !ok {
		return
	}
	var request struct {
		Action        string `json:"action"`
		Target        string `json:"target"`
		Justification string `json:"justification"`
	}
	if !decodeJSON(w, r, maxRequestBytes, &request) {
		return
	}
	if request.Action == "" || request.Target == "" || len(request.Target) > 512 || len(strings.TrimSpace(request.Justification)) < 12 || len(request.Justification) > 2_000 {
		http.Error(w, "action, target, and a 12-2000 character justification are required", http.StatusBadRequest)
		return
	}
	decision, err := m.evaluateResponsePolicy(r.Context(), actor, request.Action, request.Target, request.Justification, nil)
	if err != nil {
		http.Error(w, "policy engine unavailable; response request denied", http.StatusServiceUnavailable)
		return
	}
	id, err := randomID("RESP-")
	if err != nil {
		http.Error(w, "could not allocate response request ID", http.StatusInternalServerError)
		return
	}
	status := "denied"
	if decision.RequiresApproval {
		status = "pending_approval"
	} else if decision.Allow {
		status = "approved"
	}
	record := ResponseRequest{
		ID: id, Action: request.Action, Target: request.Target,
		Justification: request.Justification, Requester: actor,
		RequestedAt: time.Now().UTC(), Status: status, Decision: decision.AsMap(),
	}
	err = m.update(actor, "response.request", id, map[string]any{"action": request.Action, "target": request.Target, "status": status}, func(state *controlState) error {
		state.Requests[id] = record
		return nil
	})
	if err != nil {
		http.Error(w, "could not persist response request", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func (m *Manager) approveResponseRequest(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.authorize(w, r, "approver", "admin")
	if !ok {
		return
	}
	id := r.PathValue("requestID")
	m.mu.RLock()
	record, exists := m.state.Requests[id]
	m.mu.RUnlock()
	if !exists {
		http.NotFound(w, r)
		return
	}
	if record.Status != "pending_approval" {
		http.Error(w, "response request is not pending approval", http.StatusConflict)
		return
	}
	approval := &ResponseApproval{Approver: actor, At: time.Now().UTC()}
	decision, err := m.evaluateResponsePolicy(r.Context(), record.Requester, record.Action, record.Target, record.Justification, approval)
	if err != nil {
		http.Error(w, "policy engine unavailable; approval denied", http.StatusServiceUnavailable)
		return
	}
	record.Approval = approval
	record.Decision = decision.AsMap()
	if decision.Allow {
		record.Status = "approved"
	} else {
		record.Status = "denied"
	}
	err = m.update(actor, "response.approve", id, map[string]any{"status": record.Status, "action": record.Action}, func(state *controlState) error {
		current, found := state.Requests[id]
		if !found || current.Status != "pending_approval" {
			return errors.New("response request changed during approval")
		}
		state.Requests[id] = record
		return nil
	})
	if err != nil {
		http.Error(w, "could not persist response approval: "+err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (m *Manager) rejectResponseRequest(w http.ResponseWriter, r *http.Request) {
	actor, ok := m.authorize(w, r, "approver", "admin")
	if !ok {
		return
	}
	id := r.PathValue("requestID")
	err := m.update(actor, "response.reject", id, nil, func(state *controlState) error {
		record, found := state.Requests[id]
		if !found {
			return os.ErrNotExist
		}
		if record.Status != "pending_approval" {
			return errors.New("response request is not pending approval")
		}
		record.Status = "rejected"
		state.Requests[id] = record
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"request_id": id, "status": "rejected"})
}

func (m *Manager) listResponseRequests(w http.ResponseWriter, r *http.Request) {
	if !m.readAccess(w, r) {
		return
	}
	m.mu.RLock()
	requests := make([]ResponseRequest, 0, len(m.state.Requests))
	for _, request := range m.state.Requests {
		requests = append(requests, request)
	}
	m.mu.RUnlock()
	writeJSON(w, http.StatusOK, requests)
}

func (m *Manager) listAudit(w http.ResponseWriter, r *http.Request) {
	if !m.readAccess(w, r) {
		return
	}
	m.mu.RLock()
	audit := append([]AuditEntry(nil), m.state.Audit...)
	m.mu.RUnlock()
	writeJSON(w, http.StatusOK, audit)
}

func (m *Manager) verifyAudit(w http.ResponseWriter, r *http.Request) {
	if !m.readAccess(w, r) {
		return
	}
	m.mu.RLock()
	valid, head := verifyChain(m.state.Audit)
	count := len(m.state.Audit)
	m.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"valid": valid, "entry_count": count, "head_hash": head})
}

type PolicyDecision struct {
	Allow            bool   `json:"allow"`
	RequiresApproval bool   `json:"requires_approval"`
	Reason           string `json:"reason"`
}

func (d PolicyDecision) AsMap() map[string]any {
	return map[string]any{"allow": d.Allow, "requires_approval": d.RequiresApproval, "reason": d.Reason}
}

func (m *Manager) evaluateResponsePolicy(ctx context.Context, actor Actor, action, target, justification string, approval *ResponseApproval) (PolicyDecision, error) {
	input := map[string]any{
		"action": action, "target": target, "justification": justification,
		"actor": actor,
	}
	if approval != nil {
		input["approval"] = map[string]any{
			"approver_id":   approval.Approver.ID,
			"approver_role": approval.Approver.Role,
			"approved_at":   approval.At,
		}
	}
	body, _ := json.Marshal(map[string]any{"input": input})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.opaURL+"/v1/data/sentinelforge/response/decision", bytes.NewReader(body))
	if err != nil {
		return PolicyDecision{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := m.client.Do(request)
	if err != nil {
		return PolicyDecision{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return PolicyDecision{}, fmt.Errorf("OPA returned %s", response.Status)
	}
	var payload struct {
		Result PolicyDecision `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return PolicyDecision{}, err
	}
	return payload.Result, nil
}

func (m *Manager) signVersion(ruleID string, number int, title, source string, actor Actor, candidate string, rollback int) RuleVersion {
	hash := sha256.Sum256([]byte(source))
	digest := hex.EncodeToString(hash[:])
	message := fmt.Sprintf("%s:%d:%s", ruleID, number, digest)
	mac := hmac.New(sha256.New, m.signingKey)
	_, _ = mac.Write([]byte(message))
	return RuleVersion{
		RuleID: ruleID, Version: number, Title: title, RuleYAML: source,
		SHA256: digest, Signature: hex.EncodeToString(mac.Sum(nil)),
		SignedBy: actor, SignedAt: time.Now().UTC(), Candidate: candidate, RollbackOf: rollback,
	}
}

func (m *Manager) runValidator(ctx context.Context, mode string, input []byte, output any) error {
	command := exec.CommandContext(ctx, m.validator, mode)
	command.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = strings.TrimSpace(stdout.String())
		}
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("validator %s: %s", mode, message)
	}
	if err := json.Unmarshal(stdout.Bytes(), output); err != nil {
		return fmt.Errorf("validator returned invalid JSON: %w", err)
	}
	return nil
}

func (m *Manager) authorize(w http.ResponseWriter, r *http.Request, roles ...string) (Actor, bool) {
	if !m.readAccess(w, r) {
		return Actor{}, false
	}
	provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var actor Actor
	for token, record := range m.tokens {
		if hmac.Equal([]byte(provided), []byte(token)) {
			actor = record.Actor
			break
		}
	}
	if actor.ID == "" {
		http.Error(w, "valid bearer token required", http.StatusUnauthorized)
		return Actor{}, false
	}
	for _, role := range roles {
		if actor.Role == role {
			return actor, true
		}
	}
	http.Error(w, "role is not permitted for this operation", http.StatusForbidden)
	return Actor{}, false
}

func (m *Manager) readAccess(w http.ResponseWriter, r *http.Request) bool {
	if !loopbackRequest(r) {
		http.Error(w, "control-plane API is available from this machine only", http.StatusForbidden)
		return false
	}
	return m.ready(w)
}

func (m *Manager) ready(w http.ResponseWriter) bool {
	if m.loadErr != nil {
		http.Error(w, "control-plane state is unavailable", http.StatusServiceUnavailable)
		return false
	}
	return true
}

func (m *Manager) update(actor Actor, action, resource string, details map[string]any, change func(*controlState) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return m.loadErr
	}
	copyBytes, err := json.Marshal(m.state)
	if err != nil {
		return err
	}
	next := newState()
	if err := json.Unmarshal(copyBytes, &next); err != nil {
		return err
	}
	if err := change(&next); err != nil {
		return err
	}
	appendAudit(&next, actor, action, resource, details)
	if err := m.save(next); err != nil {
		return err
	}
	m.state = next
	return nil
}

func (m *Manager) load() error {
	body, err := os.ReadFile(m.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var loaded controlState
	if err := json.Unmarshal(body, &loaded); err != nil {
		return err
	}
	if loaded.Candidates == nil || loaded.Versions == nil || loaded.Requests == nil {
		return errors.New("control-plane state is missing required maps")
	}
	if valid, _ := verifyChain(loaded.Audit); !valid {
		return errors.New("control-plane audit hash chain is invalid")
	}
	m.state = loaded
	return nil
}

func (m *Manager) save(state controlState) error {
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	temporary := m.statePath + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, m.statePath)
}

func newState() controlState {
	return controlState{
		Candidates: map[string]Candidate{},
		Versions:   map[string][]RuleVersion{},
		Requests:   map[string]ResponseRequest{},
		Audit:      []AuditEntry{},
	}
}

func appendAudit(state *controlState, actor Actor, action, resource string, details map[string]any) {
	previous := ""
	if count := len(state.Audit); count > 0 {
		previous = state.Audit[count-1].Hash
	}
	entry := AuditEntry{
		Sequence: uint64(len(state.Audit) + 1), At: time.Now().UTC(), Actor: actor,
		Action: action, Resource: resource, Details: details, Previous: previous,
	}
	entry.Hash = auditHash(entry)
	state.Audit = append(state.Audit, entry)
}

func verifyChain(entries []AuditEntry) (bool, string) {
	previous := ""
	for index, entry := range entries {
		if entry.Sequence != uint64(index+1) || entry.Previous != previous || entry.Hash != auditHash(entry) {
			return false, previous
		}
		previous = entry.Hash
	}
	return true, previous
}

func auditHash(entry AuditEntry) string {
	entry.Hash = ""
	body, _ := json.Marshal(entry)
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

func randomID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}

func loadTokens(raw string) map[string]tokenRecord {
	result := map[string]tokenRecord{}
	if raw == "" {
		return result
	}
	var values map[string]tokenRecord
	if json.Unmarshal([]byte(raw), &values) != nil {
		return result
	}
	for token, record := range values {
		if token == "" || record.ID == "" || !validRole(record.Role) {
			continue
		}
		result[token] = record
	}
	return result
}

func validRole(role string) bool {
	switch role {
	case "viewer", "analyst", "approver", "admin":
		return true
	default:
		return false
	}
}

func loopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = strings.Trim(r.RemoteAddr, "[]")
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, target any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		http.Error(w, "request must contain one JSON value", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
