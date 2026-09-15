package ingest_test

import (
	"strings"
	"testing"

	"github.com/klaudtrace/klaudtrace/internal/ingest"
)

func TestIngestReader_RecordsEnvelope(t *testing.T) {
	jsonPayload := `{
		"Records": [
			{
				"eventVersion": "1.08",
				"eventTime": "2026-09-15T12:00:00Z",
				"eventSource": "sts.amazonaws.com",
				"eventName": "AssumeRole",
				"eventID": "evt-01"
			},
			{
				"eventVersion": "1.08",
				"eventTime": "2026-09-15T12:05:00Z",
				"eventSource": "s3.amazonaws.com",
				"eventName": "GetObject",
				"eventID": "evt-02"
			}
		]
	}`

	res, err := ingest.IngestReader(strings.NewReader(jsonPayload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(res.Events))
	}
	if res.Events[0].ID != "evt-01" || res.Events[1].ID != "evt-02" {
		t.Errorf("mismatched IDs: %s, %s", res.Events[0].ID, res.Events[1].ID)
	}
}

func TestIngestReader_JSONArray(t *testing.T) {
	jsonPayload := `[
		{
			"eventTime": "2026-09-15T12:00:00Z",
			"eventSource": "kms.amazonaws.com",
			"eventName": "Decrypt",
			"eventID": "kms-01"
		}
	]`

	res, err := ingest.IngestReader(strings.NewReader(jsonPayload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(res.Events))
	}
}

func TestIngestReader_JSONL(t *testing.T) {
	jsonlPayload := `{"eventTime":"2026-09-15T12:00:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","eventID":"l-01"}
{"eventTime":"2026-09-15T12:01:00Z","eventSource":"s3.amazonaws.com","eventName":"PutObject","eventID":"l-02"}`

	res, err := ingest.IngestReader(strings.NewReader(jsonlPayload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(res.Events))
	}
}

func TestIngestReader_MalformedTolerance(t *testing.T) {
	// JSONL with one valid line, one corrupted line, and one valid line
	mixedPayload := `{"eventTime":"2026-09-15T12:00:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","eventID":"m-01"}
{CORRUPTED_JSON_LINE!@#$}
{"eventTime":"2026-09-15T12:02:00Z","eventSource":"kms.amazonaws.com","eventName":"Decrypt","eventID":"m-02"}`

	res, err := ingest.IngestReader(strings.NewReader(mixedPayload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.Events) != 2 {
		t.Errorf("expected 2 valid events parsed, got %d", len(res.Events))
	}
	if len(res.Warnings) != 1 {
		t.Errorf("expected 1 warning for malformed line, got %d", len(res.Warnings))
	}
}
