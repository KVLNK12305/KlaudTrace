package ingest

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klaudtrace/klaudtrace/internal/model"
	"github.com/klaudtrace/klaudtrace/internal/parser"
)

// IngestionResult contains the parsed events along with any warnings or malformed record details.
type IngestionResult struct {
	Events   []*model.NormalizedEvent `json:"events"`
	Warnings []string                 `json:"warnings,omitempty"`
	TotalRaw int                      `json:"total_raw"`
}

// IngestFile opens and parses a CloudTrail log file (supports .json and .json.gz).
func IngestFile(path string) (*IngestionResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %q: %w", path, err)
	}
	defer f.Close()

	var reader io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gzReader, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader for %q: %w", path, err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	return IngestReader(reader)
}

// IngestReader decodes CloudTrail events from an io.Reader, supporting:
// 1. Standard CloudTrail export format: {"Records": [ ... ]}
// 2. Direct JSON array: [ ... ]
// 3. Newline-delimited JSON (JSONL): { ... }\n{ ... }
// 4. Single JSON event: { ... }
func IngestReader(r io.Reader) (*IngestionResult, error) {
	// Read full content or use buffered reader to inspect first non-whitespace byte
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read input stream: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return &IngestionResult{}, nil
	}

	result := &IngestionResult{
		Events:   make([]*model.NormalizedEvent, 0),
		Warnings: make([]string, 0),
	}

	// Case 1 & 2: Starts with '{' or '['
	if trimmed[0] == '{' {
		// Attempt standard CloudTrail {"Records": [...]} envelope
		var envelope struct {
			Records []json.RawMessage `json:"Records"`
		}
		if err := json.Unmarshal(trimmed, &envelope); err == nil && envelope.Records != nil {
			result.TotalRaw = len(envelope.Records)
			for i, rawMsg := range envelope.Records {
				parseSingleRawMessage(rawMsg, i, result)
			}
			return result, nil
		}

		// Attempt single JSON event
		var singleRaw parser.RawCloudTrailEvent
		if err := json.Unmarshal(trimmed, &singleRaw); err == nil && (singleRaw.EventName != "" || singleRaw.EventSource != "") {
			singleRaw.Raw = trimmed
			result.TotalRaw = 1
			norm, err := parser.ParseRawEvent(&singleRaw, 0)
			if err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Record #0: failed to normalize: %v", err))
			} else {
				result.Events = append(result.Events, norm)
			}
			return result, nil
		}
	}

	if trimmed[0] == '[' {
		var rawArray []json.RawMessage
		if err := json.Unmarshal(trimmed, &rawArray); err == nil {
			result.TotalRaw = len(rawArray)
			for i, rawMsg := range rawArray {
				parseSingleRawMessage(rawMsg, i, result)
			}
			return result, nil
		}
	}

	// Case 3: Line-delimited JSON (JSONL)
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	// Allow large lines (e.g. 10MB) for big CloudTrail events
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	lineIndex := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		lineIndex++
		result.TotalRaw++
		parseSingleRawMessage(line, lineIndex-1, result)
	}

	if err := scanner.Err(); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Scanner error: %v", err))
	}

	if len(result.Events) == 0 && len(result.Warnings) > 0 {
		return result, fmt.Errorf("no valid CloudTrail events could be parsed (%d warnings)", len(result.Warnings))
	}

	return result, nil
}

func parseSingleRawMessage(msg json.RawMessage, index int, result *IngestionResult) {
	var raw parser.RawCloudTrailEvent
	if err := json.Unmarshal(msg, &raw); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Record #%d: malformed JSON: %v", index, err))
		return
	}
	raw.Raw = msg
	norm, err := parser.ParseRawEvent(&raw, index)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Record #%d: normalization error: %v", index, err))
		return
	}
	result.Events = append(result.Events, norm)
}
