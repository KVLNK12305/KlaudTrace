package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/klaudtrace/klaudtrace/internal/analysis"
	"github.com/klaudtrace/klaudtrace/internal/classification"
	"github.com/klaudtrace/klaudtrace/internal/correlation"
	"github.com/klaudtrace/klaudtrace/internal/ingest"
	"github.com/klaudtrace/klaudtrace/internal/model"
	"github.com/klaudtrace/klaudtrace/internal/report"
)

func runPipeline(t *testing.T, fixturePath string) *model.IncidentSummary {
	t.Helper()
	res, err := ingest.IngestFile(fixturePath)
	if err != nil {
		t.Fatalf("failed ingesting %s: %v", fixturePath, err)
	}

	classifier := classification.New()
	events, _ := correlation.CorrelatePipeline(res.Events, classifier)
	groups := correlation.GroupBySession(events)
	paths := analysis.ReconstructPaths(groups)
	findings := analysis.EvaluateImpact(events, paths, groups)
	return analysis.GenerateIncidentSummary(events, paths, findings)
}

func TestE2E_Scenario1(t *testing.T) {
	summary := runPipeline(t, "../fixtures/cloudtrail/scenario1/events.json")

	if summary.TotalEvents != 4 {
		t.Errorf("expected 4 events, got %d", summary.TotalEvents)
	}
	if len(summary.Identities) != 2 {
		t.Fatalf("expected 2 identities, got %d", len(summary.Identities))
	}
	if len(summary.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(summary.Paths))
	}
	if len(summary.Findings) != 2 {
		t.Fatalf("expected 2 impact findings, got %d", len(summary.Findings))
	}

	// Verify path 2 has correlated DevJoe parent
	path2 := summary.Paths[1]
	if path2.Confidence != model.ConfidenceCorrelated {
		t.Errorf("expected path2 confidence CORRELATED, got %s", path2.Confidence)
	}
}

func TestE2E_Scenario2(t *testing.T) {
	summary := runPipeline(t, "../fixtures/cloudtrail/scenario2/events.json")

	if summary.TotalEvents != 2 {
		t.Errorf("expected 2 events, got %d", summary.TotalEvents)
	}
	if len(summary.Findings) != 1 {
		t.Fatalf("expected 1 KMS finding, got %d", len(summary.Findings))
	}
	if summary.Findings[0].AffectedResources[0].Name != "alias/payment-token-key" {
		t.Errorf("unexpected affected resource: %s", summary.Findings[0].AffectedResources[0].Name)
	}
}

func TestE2E_Scenario3(t *testing.T) {
	summary := runPipeline(t, "../fixtures/cloudtrail/scenario3/events.json")

	if summary.TotalEvents != 5 {
		t.Errorf("expected 5 events, got %d", summary.TotalEvents)
	}
	if len(summary.Findings) != 2 {
		t.Fatalf("expected 2 findings (privilege escalation + audit deletion), got %d", len(summary.Findings))
	}

	foundTrailDeletion := false
	for _, f := range summary.Findings {
		if f.Title == "Observed Audit Trail / Resource Deletion" {
			foundTrailDeletion = true
		}
	}
	if !foundTrailDeletion {
		t.Errorf("expected Audit Trail Deletion finding")
	}
}

func TestE2E_Scenario4(t *testing.T) {
	summary := runPipeline(t, "../fixtures/cloudtrail/scenario4/events.json")

	if summary.TotalEvents != 2 {
		t.Errorf("expected 2 events, got %d", summary.TotalEvents)
	}

	foundDataMovement := false
	for _, f := range summary.Findings {
		if f.Title == "Observed Cross-Bucket Data Movement" {
			foundDataMovement = true
			if f.Confidence != model.ConfidenceCorrelated {
				t.Errorf("expected CORRELATED confidence for cross-bucket movement, got %s", f.Confidence)
			}
		}
	}
	if !foundDataMovement {
		t.Errorf("expected Cross-Bucket Data Movement finding")
	}
}

func TestE2E_Benign(t *testing.T) {
	summary := runPipeline(t, "../fixtures/cloudtrail/benign/events.json")

	if len(summary.Findings) != 0 {
		t.Errorf("expected 0 impact findings for benign traffic, got %d", len(summary.Findings))
	}
	if summary.AssessmentStatement == "" {
		t.Errorf("expected non-empty assessment statement")
	}
}

func TestE2E_Determinism(t *testing.T) {
	// Execute Scenario 1 multiple times and assert identical SHA-256 hash of JSON output
	var firstHash string

	for i := 0; i < 25; i++ {
		summary := runPipeline(t, "../fixtures/cloudtrail/scenario1/events.json")
		jsonBytes, err := report.RenderJSON(summary)
		if err != nil {
			t.Fatalf("failed JSON render: %v", err)
		}

		h := sha256.Sum256(jsonBytes)
		currentHash := hex.EncodeToString(h[:])

		if i == 0 {
			firstHash = currentHash
		} else if currentHash != firstHash {
			t.Fatalf("nondeterministic output detected on iteration %d! Hash %s != %s", i, currentHash, firstHash)
		}
	}
}

func TestE2E_GoldenMatch(t *testing.T) {
	scenarios := []string{"scenario1", "scenario2", "scenario3", "scenario4", "benign"}

	for _, sc := range scenarios {
		t.Run(sc, func(t *testing.T) {
			inputPath := "../fixtures/cloudtrail/" + sc + "/events.json"
			summary := runPipeline(t, inputPath)

			// 1. Verify JSON matches golden file
			jsonBytes, err := report.RenderJSON(summary)
			if err != nil {
				t.Fatalf("failed JSON render: %v", err)
			}
			goldenJSON, err := os.ReadFile("golden/" + sc + ".json")
			if err != nil {
				t.Fatalf("failed reading golden JSON: %v", err)
			}
			if string(jsonBytes) != string(goldenJSON) {
				t.Errorf("rendered JSON did not match golden file for %s", sc)
			}

			// 2. Verify Markdown matches golden file
			mdText := report.RenderMarkdown(summary)
			goldenMD, err := os.ReadFile("golden/" + sc + ".md")
			if err != nil {
				t.Fatalf("failed reading golden Markdown: %v", err)
			}
			if mdText != string(goldenMD) {
				t.Errorf("rendered Markdown did not match golden file for %s", sc)
			}
		})
	}
}
