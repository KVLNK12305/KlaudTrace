package report_test

import (
	"strings"
	"testing"
	"time"

	"github.com/klaudtrace/klaudtrace/internal/model"
	"github.com/klaudtrace/klaudtrace/internal/report"
)

func TestRenderOutputs(t *testing.T) {
	summary := &model.IncidentSummary{
		TimeWindowStart: time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
		TimeWindowEnd:   time.Date(2026, 9, 15, 12, 15, 0, 0, time.UTC),
		TotalEvents:     5,
		ParsedEvents:    5,
		Identities: []model.IdentityRef{
			{UserName: "DevJoe", Type: model.IdentityTypeIAMUser},
		},
		AffectedAssets: []model.ResourceRef{
			{
				Name: "payflow-transaction-data",
				Type: model.ResourceTypeS3Bucket,
				Classification: &model.AssetClassification{
					Domain:      "fintech",
					AssetType:   "transaction_data",
					Sensitivity: model.SensitivityCritical,
				},
			},
		},
		Paths: []model.ObservedPath{
			{
				ID:         "path-1",
				Title:      "Test Path",
				Confidence: model.ConfidenceObserved,
				Nodes: []model.ObservedPathNode{
					{Type: model.PathNodeIdentity, Label: "DevJoe"},
					{Type: model.PathNodeAction, Label: "s3:GetObject"},
				},
			},
		},
		Findings: []model.ImpactFinding{
			{
				ID:          "f-1",
				Title:       "Access to Transaction Data",
				Description: "Evidence shows s3:GetObject on transaction data.",
				Severity:    model.SensitivityCritical,
				Confidence:  model.ConfidenceObserved,
				Limitations: "Exfiltration not established.",
			},
		},
		AssessmentStatement: "CloudTrail evidence establishes access to transaction data.",
	}

	// 1. Text rendering
	text := report.RenderText(summary)
	if !strings.Contains(text, "KLAUDTRACE INCIDENT ANALYSIS") {
		t.Errorf("expected header in text output")
	}
	if !strings.Contains(text, "payflow-transaction-data") {
		t.Errorf("expected asset name in text output")
	}

	// 2. JSON rendering
	jsonBytes, err := report.RenderJSON(summary)
	if err != nil {
		t.Fatalf("failed rendering JSON: %v", err)
	}
	if len(jsonBytes) == 0 {
		t.Errorf("empty JSON output")
	}

	// 3. Markdown rendering
	md := report.RenderMarkdown(summary)
	if !strings.Contains(md, "# KlaudTrace Incident Reconstruction Report") {
		t.Errorf("expected title in Markdown output")
	}
	if !strings.Contains(md, "```mermaid") {
		t.Errorf("expected mermaid flowchart in Markdown output")
	}
}
