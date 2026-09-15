package analysis_test

import (
	"testing"
	"time"

	"github.com/klaudtrace/klaudtrace/internal/analysis"
	"github.com/klaudtrace/klaudtrace/internal/classification"
	"github.com/klaudtrace/klaudtrace/internal/correlation"
	"github.com/klaudtrace/klaudtrace/internal/model"
)

func TestAnalysis_Scenario1_TransactionAccess(t *testing.T) {
	classifier := classification.New()
	t0 := time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC)

	// Event 1: AssumeRole
	evt1 := &model.NormalizedEvent{
		ID:        "evt-01",
		Timestamp: t0,
		Action:    model.NormalizeAction("sts", "AssumeRole"),
		Identity: model.IdentityRef{
			Type:     model.IdentityTypeIAMUser,
			UserName: "DevJoe",
			ARN:      "arn:aws:iam::123456789012:user/DevJoe",
		},
		RequestParameters: map[string]any{
			"roleArn":         "arn:aws:iam::123456789012:role/PaymentServiceRole",
			"roleSessionName": "DevJoe",
		},
		ResponseElements: map[string]any{
			"credentials": map[string]any{"accessKeyId": "ASIA_TEST_1"},
			"assumedRoleUser": map[string]any{
				"arn":           "arn:aws:sts::123456789012:assumed-role/PaymentServiceRole/DevJoe",
				"assumedRoleId": "AROA:DevJoe",
			},
		},
		SourceRef: model.EvidenceRef{EventID: "evt-01", RecordIndex: 0, EventName: "AssumeRole"},
	}

	// Event 2: s3:GetObject on transaction data
	evt2 := &model.NormalizedEvent{
		ID:        "evt-02",
		Timestamp: t0.Add(1 * time.Minute),
		Action:    model.NormalizeAction("s3", "GetObject"),
		Identity: model.IdentityRef{
			Type:              model.IdentityTypeAssumedRole,
			ARN:               "arn:aws:sts::123456789012:assumed-role/PaymentServiceRole/DevJoe",
			SessionIssuerARN:  "arn:aws:iam::123456789012:role/PaymentServiceRole",
			SessionIssuerName: "PaymentServiceRole",
			SessionName:       "DevJoe",
			AccessKeyID:       "ASIA_TEST_1",
		},
		Resources: []model.ResourceRef{
			{
				Type: model.ResourceTypeS3Object,
				Name: "payflow-transaction-data/2026/09/tx.csv",
			},
		},
		SourceRef: model.EvidenceRef{EventID: "evt-02", RecordIndex: 1, EventName: "GetObject"},
	}

	// Event 3: kms:Decrypt
	evt3 := &model.NormalizedEvent{
		ID:        "evt-03",
		Timestamp: t0.Add(2 * time.Minute),
		Action:    model.NormalizeAction("kms", "Decrypt"),
		Identity: model.IdentityRef{
			Type:              model.IdentityTypeAssumedRole,
			ARN:               "arn:aws:sts::123456789012:assumed-role/PaymentServiceRole/DevJoe",
			SessionIssuerARN:  "arn:aws:iam::123456789012:role/PaymentServiceRole",
			SessionIssuerName: "PaymentServiceRole",
			SessionName:       "DevJoe",
			AccessKeyID:       "ASIA_TEST_1",
		},
		Resources: []model.ResourceRef{
			{
				Type: model.ResourceTypeKMSKey,
				Name: "alias/payment-token-key",
			},
		},
		SourceRef: model.EvidenceRef{EventID: "evt-03", RecordIndex: 2, EventName: "Decrypt"},
	}

	// Run correlation pipeline
	rawEvents := []*model.NormalizedEvent{evt2, evt1, evt3} // Out of order input
	events, _ := correlation.CorrelatePipeline(rawEvents, classifier)
	groups := correlation.GroupBySession(events)

	paths := analysis.ReconstructPaths(groups)
	if len(paths) == 0 {
		t.Fatalf("expected reconstructed paths, got 0")
	}

	findings := analysis.EvaluateImpact(events, paths, groups)
	if len(findings) == 0 {
		t.Fatalf("expected impact findings, got 0")
	}

	summary := analysis.GenerateIncidentSummary(events, paths, findings)

	// Verify identity was properly correlated to DevJoe
	foundDevJoe := false
	for _, id := range summary.Identities {
		if id.DisplayName() == "DevJoe" {
			foundDevJoe = true
			break
		}
	}
	if !foundDevJoe {
		t.Errorf("expected DevJoe in incident identities")
	}

	// Verify affected assets
	if len(summary.AffectedAssets) == 0 {
		t.Errorf("expected affected classified assets")
	}

	// Verify assessment statement does NOT claim exfiltration
	if summary.AssessmentStatement == "" {
		t.Errorf("expected non-empty assessment statement")
	}
}
