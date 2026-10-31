package ingest

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var categories = map[string]bool{
	"process": true, "authentication": true, "file": true,
	"service": true, "persistence": true, "network": true,
}

func (e Event) Validate() error {
	if strings.TrimSpace(e.EventID) == "" {
		return errors.New("event_id is required")
	}
	if _, err := time.Parse(time.RFC3339Nano, e.Timestamp); err != nil {
		return errors.New("timestamp must be RFC3339")
	}
	if e.Host.HostID == "" || e.Host.OS == "" || e.Host.AgentVersion == "" {
		return errors.New("host.host_id, host.os, and host.agent_version are required")
	}
	if !categories[e.Category] {
		return fmt.Errorf("unsupported category %q", e.Category)
	}
	if strings.TrimSpace(e.Action) == "" {
		return errors.New("action is required")
	}
	if e.SchemaVersion != "1.0" {
		return errors.New("schema_version must be 1.0")
	}

	details := map[string]bool{
		"process":        len(e.Process) != 0,
		"authentication": len(e.Authentication) != 0,
		"file":           len(e.File) != 0,
		"service":        len(e.Service) != 0,
		"persistence":    len(e.Persistence) != 0,
		"network":        len(e.Network) != 0,
	}
	count := 0
	for _, present := range details {
		if present {
			count++
		}
	}
	if count != 1 || !details[e.Category] {
		return errors.New("exactly one details object matching category is required")
	}
	return nil
}
