package report

import (
	"encoding/json"

	"github.com/klaudtrace/klaudtrace/internal/model"
)

// RenderJSON serializes the incident summary to indented JSON.
func RenderJSON(summary *model.IncidentSummary) ([]byte, error) {
	return json.MarshalIndent(summary, "", "  ")
}
