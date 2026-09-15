package parser_test

import (
	"testing"
	"time"

	"github.com/klaudtrace/klaudtrace/internal/model"
	"github.com/klaudtrace/klaudtrace/internal/parser"
)

func TestParseRawEvent_Standard(t *testing.T) {
	raw := &parser.RawCloudTrailEvent{
		EventVersion: "1.08",
		EventTime:    "2026-09-15T10:00:00Z",
		EventSource:  "s3.amazonaws.com",
		EventName:    "GetObject",
		AWSRegion:    "us-east-1",
		SourceIPAddress: "198.51.100.25",
		UserAgent:    "aws-cli/2.0",
		EventID:      "test-uuid-1",
		UserIdentity: &parser.RawUserIdentity{
			Type:        "IAMUser",
			PrincipalID: "AIDAEXAMPLE",
			ARN:         "arn:aws:iam::123456789012:user/DevJoe",
			AccountID:   "123456789012",
			UserName:    "DevJoe",
		},
	}

	norm, err := parser.ParseRawEvent(raw, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if norm.ID != "test-uuid-1" {
		t.Errorf("expected ID test-uuid-1, got %s", norm.ID)
	}
	if norm.Timestamp != time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC) {
		t.Errorf("unexpected timestamp: %v", norm.Timestamp)
	}
	if norm.Identity.Type != model.IdentityTypeIAMUser {
		t.Errorf("expected IdentityType IAMUser, got %s", norm.Identity.Type)
	}
	if norm.Identity.UserName != "DevJoe" {
		t.Errorf("expected UserName DevJoe, got %s", norm.Identity.UserName)
	}
	if norm.Action.Normalized != "s3:GetObject" {
		t.Errorf("expected action s3:GetObject, got %s", norm.Action.Normalized)
	}
	if !norm.Action.IsDataRead {
		t.Errorf("expected IsDataRead = true")
	}
	if !norm.ReadOnly {
		t.Errorf("expected ReadOnly = true")
	}
}

func TestParseRawEvent_AssumedRole(t *testing.T) {
	raw := &parser.RawCloudTrailEvent{
		EventTime:   "2026-09-15T10:05:00Z",
		EventSource: "kms.amazonaws.com",
		EventName:   "Decrypt",
		EventID:     "kms-event-1",
		UserIdentity: &parser.RawUserIdentity{
			Type:        "AssumedRole",
			PrincipalID: "AROAEXAMPLE:DevJoe",
			ARN:         "arn:aws:sts::123456789012:assumed-role/PaymentServiceRole/DevJoe",
			AccountID:   "123456789012",
			SessionContext: &parser.RawSessionContext{
				SessionIssuer: &parser.RawSessionIssuer{
					Type:        "Role",
					PrincipalID: "AROAEXAMPLE",
					ARN:         "arn:aws:iam::123456789012:role/PaymentServiceRole",
					AccountID:   "123456789012",
					UserName:    "PaymentServiceRole",
				},
			},
		},
	}

	norm, err := parser.ParseRawEvent(raw, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if norm.Identity.Type != model.IdentityTypeAssumedRole {
		t.Errorf("expected AssumedRole, got %s", norm.Identity.Type)
	}
	if norm.Identity.SessionIssuerName != "PaymentServiceRole" {
		t.Errorf("expected SessionIssuerName PaymentServiceRole, got %s", norm.Identity.SessionIssuerName)
	}
	if norm.Identity.SessionName != "DevJoe" {
		t.Errorf("expected SessionName DevJoe, got %s", norm.Identity.SessionName)
	}
	if norm.Identity.DisplayName() != "PaymentServiceRole/DevJoe" {
		t.Errorf("expected DisplayName PaymentServiceRole/DevJoe, got %s", norm.Identity.DisplayName())
	}
}

func TestParseRawEvent_MissingFields(t *testing.T) {
	// Completely missing optional fields should not crash or error
	raw := &parser.RawCloudTrailEvent{
		EventSource: "s3.amazonaws.com",
		EventName:   "ListBuckets",
	}

	norm, err := parser.ParseRawEvent(raw, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if norm.ID == "" {
		t.Errorf("expected generated deterministic ID, got empty")
	}
	if norm.Identity.Type != model.IdentityTypeUnknown {
		t.Errorf("expected Unknown identity, got %s", norm.Identity.Type)
	}
}

func TestNormalizeAction_Flags(t *testing.T) {
	act1 := model.NormalizeAction("iam", "CreateRole")
	if !act1.IsPrivileged {
		t.Errorf("expected CreateRole to be privileged")
	}

	act2 := model.NormalizeAction("cloudtrail.amazonaws.com", "DeleteTrail")
	if !act2.IsDestructive || !act2.IsPrivileged {
		t.Errorf("expected DeleteTrail to be destructive and privileged")
	}

	act3 := model.NormalizeAction("sts", "AssumeRole")
	if !act3.IsCredentialAccess {
		t.Errorf("expected AssumeRole to be credential access")
	}
}
