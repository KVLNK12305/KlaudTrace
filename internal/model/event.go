package model

import (
	"fmt"
	"time"
)

// ConfidenceLevel represents how firmly a finding or correlation is established.
type ConfidenceLevel string

const (
	// ConfidenceObserved means directly evidenced within a single record.
	ConfidenceObserved ConfidenceLevel = "OBSERVED"
	// ConfidenceCorrelated means linked across events by explicit tokens, session IDs, or request-response pairs.
	ConfidenceCorrelated ConfidenceLevel = "CORRELATED"
	// ConfidenceInferred means a plausible operational relationship based on temporal proximity and context.
	ConfidenceInferred ConfidenceLevel = "INFERRED"
	// ConfidenceUndetermined means the relationship cannot be established from available logs.
	ConfidenceUndetermined ConfidenceLevel = "UNDETERMINED"
)

// EvidenceRef preserves source event traceability.
type EvidenceRef struct {
	EventID       string            `json:"event_id"`
	RecordIndex   int               `json:"record_index"`
	Timestamp     time.Time         `json:"timestamp"`
	EventSource   string            `json:"event_source"`
	EventName     string            `json:"event_name"`
	SourceIP      string            `json:"source_ip,omitempty"`
	FieldEvidence map[string]string `json:"field_evidence,omitempty"`
}

func (e EvidenceRef) String() string {
	if e.EventID != "" {
		return fmt.Sprintf("Event %s (#%d %s:%s at %s)", e.EventID, e.RecordIndex, e.EventSource, e.EventName, e.Timestamp.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("Record #%d (%s:%s at %s)", e.RecordIndex, e.EventSource, e.EventName, e.Timestamp.UTC().Format(time.RFC3339))
}

// NormalizedEvent is the internal canonical representation of a CloudTrail event.
type NormalizedEvent struct {
	ID                 string         `json:"id"`
	Timestamp          time.Time      `json:"timestamp"`
	EventSource        string         `json:"event_source"`
	EventName          string         `json:"event_name"`
	AWSExecutionRegion string         `json:"aws_region,omitempty"`
	SourceIPAddress    string         `json:"source_ip_address,omitempty"`
	UserAgent          string         `json:"user_agent,omitempty"`
	Identity           IdentityRef    `json:"identity"`
	Action             ActionRef      `json:"action"`
	Resources          []ResourceRef  `json:"resources,omitempty"`
	RequestParameters  map[string]any `json:"request_parameters,omitempty"`
	ResponseElements   map[string]any `json:"response_elements,omitempty"`
	ErrorCode          string         `json:"error_code,omitempty"`
	ErrorMessage       string         `json:"error_message,omitempty"`
	ReadOnly           bool           `json:"read_only"`
	EventType          string         `json:"event_type,omitempty"`
	SourceRef          EvidenceRef    `json:"source_ref"`
	RawJSON            []byte         `json:"-"`
}

func (e *NormalizedEvent) IsError() bool {
	return e.ErrorCode != "" || e.ErrorMessage != ""
}
