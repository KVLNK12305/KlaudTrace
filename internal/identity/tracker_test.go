package identity_test

import (
	"testing"
	"time"

	"github.com/klaudtrace/klaudtrace/internal/identity"
	"github.com/klaudtrace/klaudtrace/internal/model"
)

func TestTracker_Case1_IAMUserToAssumedRole(t *testing.T) {
	tracker := identity.NewTracker()

	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	// Event 1: DevJoe assumes PaymentServiceRole
	assumeEvt := &model.NormalizedEvent{
		ID:        "evt-assume",
		Timestamp: now,
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
			"credentials": map[string]any{
				"accessKeyId": "ASIAPAYMENTKEY123",
			},
			"assumedRoleUser": map[string]any{
				"arn":           "arn:aws:sts::123456789012:assumed-role/PaymentServiceRole/DevJoe",
				"assumedRoleId": "AROAPAYMENT:DevJoe",
			},
		},
	}

	tracker.RegisterAssumeRole(assumeEvt)

	// Event 2: Assumed role executes s3:GetObject with matching AccessKeyID
	downstreamEvt := &model.NormalizedEvent{
		ID:        "evt-s3-get",
		Timestamp: now.Add(2 * time.Minute),
		Action:    model.NormalizeAction("s3", "GetObject"),
		Identity: model.IdentityRef{
			Type:              model.IdentityTypeAssumedRole,
			ARN:               "arn:aws:sts::123456789012:assumed-role/PaymentServiceRole/DevJoe",
			SessionIssuerARN:  "arn:aws:iam::123456789012:role/PaymentServiceRole",
			SessionIssuerName: "PaymentServiceRole",
			SessionName:       "DevJoe",
			AccessKeyID:       "ASIAPAYMENTKEY123",
		},
	}

	tracker.CorrelateEvent(downstreamEvt)

	if downstreamEvt.Identity.CorrelationConfidence != model.ConfidenceCorrelated {
		t.Fatalf("expected confidence CORRELATED, got %s", downstreamEvt.Identity.CorrelationConfidence)
	}
	if downstreamEvt.Identity.ParentIdentity == nil {
		t.Fatalf("expected ParentIdentity, got nil")
	}
	if downstreamEvt.Identity.ParentIdentity.UserName != "DevJoe" {
		t.Errorf("expected parent user DevJoe, got %s", downstreamEvt.Identity.ParentIdentity.UserName)
	}
}

func TestTracker_Case2_RoleChaining(t *testing.T) {
	tracker := identity.NewTracker()
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	// Step 1: User DevJoe assumes Role A
	assumeEvt1 := &model.NormalizedEvent{
		ID:        "evt-assume-1",
		Timestamp: now,
		Action:    model.NormalizeAction("sts", "AssumeRole"),
		Identity: model.IdentityRef{
			Type:     model.IdentityTypeIAMUser,
			UserName: "DevJoe",
		},
		RequestParameters: map[string]any{
			"roleArn":         "arn:aws:iam::123456789012:role/RoleA",
			"roleSessionName": "SessionA",
		},
		ResponseElements: map[string]any{
			"credentials": map[string]any{"accessKeyId": "ASIA_A"},
		},
	}
	tracker.RegisterAssumeRole(assumeEvt1)

	// Step 2: Session A assumes Role B
	assumeEvt2 := &model.NormalizedEvent{
		ID:        "evt-assume-2",
		Timestamp: now.Add(1 * time.Minute),
		Action:    model.NormalizeAction("sts", "AssumeRole"),
		Identity: model.IdentityRef{
			Type:              model.IdentityTypeAssumedRole,
			SessionIssuerName: "RoleA",
			SessionName:       "SessionA",
			AccessKeyID:       "ASIA_A",
		},
		RequestParameters: map[string]any{
			"roleArn":         "arn:aws:iam::123456789012:role/RoleB",
			"roleSessionName": "SessionB",
		},
		ResponseElements: map[string]any{
			"credentials": map[string]any{"accessKeyId": "ASIA_B"},
		},
	}
	tracker.CorrelateEvent(assumeEvt2)
	tracker.RegisterAssumeRole(assumeEvt2)

	// Step 3: Session B calls API
	apiEvt := &model.NormalizedEvent{
		ID:        "evt-api",
		Timestamp: now.Add(2 * time.Minute),
		Action:    model.NormalizeAction("s3", "GetObject"),
		Identity: model.IdentityRef{
			Type:              model.IdentityTypeAssumedRole,
			SessionIssuerName: "RoleB",
			SessionName:       "SessionB",
			AccessKeyID:       "ASIA_B",
		},
	}
	tracker.CorrelateEvent(apiEvt)

	if apiEvt.Identity.CorrelationConfidence != model.ConfidenceCorrelated {
		t.Fatalf("expected confidence CORRELATED, got %s", apiEvt.Identity.CorrelationConfidence)
	}
	if apiEvt.Identity.ParentIdentity == nil {
		t.Fatalf("expected parent for SessionB")
	}
	if apiEvt.Identity.ParentIdentity.SessionIssuerName != "RoleA" {
		t.Errorf("expected direct parent RoleA, got %s", apiEvt.Identity.ParentIdentity.SessionIssuerName)
	}
	if apiEvt.Identity.ParentIdentity.ParentIdentity == nil || apiEvt.Identity.ParentIdentity.ParentIdentity.UserName != "DevJoe" {
		t.Errorf("expected root ancestor DevJoe")
	}
}

func TestTracker_Case3_ServiceRoleNoAssumeRole(t *testing.T) {
	tracker := identity.NewTracker()
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	// Service role performing actions directly (e.g. Lambda execution role)
	evt := &model.NormalizedEvent{
		ID:        "evt-service",
		Timestamp: now,
		Action:    model.NormalizeAction("sqs", "ReceiveMessage"),
		Identity: model.IdentityRef{
			Type:              model.IdentityTypeAssumedRole,
			SessionIssuerARN:  "arn:aws:iam::123456789012:role/PaymentServiceRole",
			SessionIssuerName: "PaymentServiceRole",
			SessionName:       "i-1234567890abcdef0", // EC2 instance or Lambda container
			AccessKeyID:       "ASIA_UNKNOWN_ASSUME",
		},
	}

	tracker.CorrelateEvent(evt)

	// Must be UNDETERMINED parent without crashing or inventing a fake user
	if evt.Identity.CorrelationConfidence != model.ConfidenceUndetermined {
		t.Errorf("expected UNDETERMINED confidence, got %s", evt.Identity.CorrelationConfidence)
	}
	if evt.Identity.ParentIdentity != nil {
		t.Errorf("expected nil parent identity for unobserved assume, got %+v", evt.Identity.ParentIdentity)
	}
}

func TestTracker_Case4_IncompleteEvidence(t *testing.T) {
	tracker := identity.NewTracker()
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	// Log contains assumed-role event, but the AssumeRole event is outside the window
	evt := &model.NormalizedEvent{
		ID:        "evt-orphan",
		Timestamp: now,
		Action:    model.NormalizeAction("kms", "Decrypt"),
		Identity: model.IdentityRef{
			Type:              model.IdentityTypeAssumedRole,
			SessionIssuerName: "UnknownRole",
			SessionName:       "UnknownSession",
			AccessKeyID:       "ASIA_ORPHAN",
		},
	}

	tracker.CorrelateEvent(evt)

	if evt.Identity.CorrelationConfidence != model.ConfidenceUndetermined {
		t.Errorf("expected UNDETERMINED confidence, got %s", evt.Identity.CorrelationConfidence)
	}
	if evt.Identity.ParentIdentity != nil {
		t.Errorf("expected nil parent, got %+v", evt.Identity.ParentIdentity)
	}
}
