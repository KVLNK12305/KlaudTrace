package resource_test

import (
	"testing"

	"github.com/klaudtrace/klaudtrace/internal/model"
	"github.com/klaudtrace/klaudtrace/internal/parser"
	"github.com/klaudtrace/klaudtrace/internal/resource"
)

func TestExtractResources_S3Object(t *testing.T) {
	raw := &parser.RawCloudTrailEvent{
		Resources: []parser.RawResource{
			{
				Type: "AWS::S3::Object",
				ARN:  "arn:aws:s3:::payflow-transaction-data/2026/09/transactions.csv",
			},
		},
	}
	norm := &model.NormalizedEvent{
		Action: model.NormalizeAction("s3", "GetObject"),
		RequestParameters: map[string]any{
			"bucketName": "payflow-transaction-data",
			"key":        "2026/09/transactions.csv",
		},
	}

	resources := resource.ExtractResources(raw, norm)
	if len(resources) == 0 {
		t.Fatalf("expected extracted resources, got none")
	}

	foundObject := false
	for _, r := range resources {
		if r.Type == model.ResourceTypeS3Object {
			foundObject = true
			if r.Name != "payflow-transaction-data/2026/09/transactions.csv" {
				t.Errorf("unexpected name: %s", r.Name)
			}
		}
	}
	if !foundObject {
		t.Errorf("expected S3 object resource")
	}
}

func TestExtractResources_KMSKey(t *testing.T) {
	norm := &model.NormalizedEvent{
		Action: model.NormalizeAction("kms", "Decrypt"),
		RequestParameters: map[string]any{
			"keyId": "alias/payment-token-key",
		},
	}

	resources := resource.ExtractResources(nil, norm)
	if len(resources) != 1 {
		t.Fatalf("expected 1 KMS resource, got %d", len(resources))
	}
	if resources[0].Type != model.ResourceTypeKMSKey {
		t.Errorf("expected KMS key type, got %s", resources[0].Type)
	}
	if resources[0].Name != "alias/payment-token-key" {
		t.Errorf("expected key name alias/payment-token-key, got %s", resources[0].Name)
	}
}

func TestExtractResources_IAMRoleAndCloudTrail(t *testing.T) {
	normRole := &model.NormalizedEvent{
		Action: model.NormalizeAction("iam", "CreateRole"),
		Identity: model.IdentityRef{
			AccountID: "123456789012",
		},
		RequestParameters: map[string]any{
			"roleName": "BackdoorAdminRole",
		},
	}
	resRole := resource.ExtractResources(nil, normRole)
	if len(resRole) != 1 || resRole[0].Type != model.ResourceTypeIAMRole || resRole[0].Name != "BackdoorAdminRole" {
		t.Errorf("failed extracting IAM role: %+v", resRole)
	}

	normTrail := &model.NormalizedEvent{
		Action: model.NormalizeAction("cloudtrail", "DeleteTrail"),
		Identity: model.IdentityRef{
			AccountID: "123456789012",
		},
		RequestParameters: map[string]any{
			"name": "payflow-audit-trail",
		},
	}
	resTrail := resource.ExtractResources(nil, normTrail)
	if len(resTrail) != 1 || resTrail[0].Type != model.ResourceTypeCloudTrail || resTrail[0].Name != "payflow-audit-trail" {
		t.Errorf("failed extracting CloudTrail trail: %+v", resTrail)
	}
}
