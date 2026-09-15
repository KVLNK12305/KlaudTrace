package model

import (
	"fmt"
)

// SensitivityLevel denotes the sensitivity classification of an asset.
type SensitivityLevel string

const (
	SensitivityCritical      SensitivityLevel = "CRITICAL"
	SensitivityHigh          SensitivityLevel = "HIGH"
	SensitivityMedium        SensitivityLevel = "MEDIUM"
	SensitivityLow           SensitivityLevel = "LOW"
	SensitivityInformational SensitivityLevel = "INFORMATIONAL"
)

// AssetClassification provides fintech and compliance classification context for an AWS resource.
type AssetClassification struct {
	Domain      string           `json:"domain"`       // e.g. "fintech", "compliance", "security"
	AssetType   string           `json:"asset_type"`   // e.g. "transaction_data", "kyc_data", "payment_credentials"
	Sensitivity SensitivityLevel `json:"sensitivity"`  // CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
	Description string           `json:"description"`  // Human-readable description
	RuleSource  string           `json:"rule_source"`  // Which rule classified this
}

// ResourceType categorizes the AWS resource.
type ResourceType string

const (
	ResourceTypeS3Bucket       ResourceType = "s3:bucket"
	ResourceTypeS3Object       ResourceType = "s3:object"
	ResourceTypeKMSKey         ResourceType = "kms:key"
	ResourceTypeSQSQueue       ResourceType = "sqs:queue"
	ResourceTypeIAMRole        ResourceType = "iam:role"
	ResourceTypeIAMPolicy      ResourceType = "iam:policy"
	ResourceTypeIAMUser        ResourceType = "iam:user"
	ResourceTypeCloudTrail     ResourceType = "cloudtrail:trail"
	ResourceTypeDynamoDBTable  ResourceType = "dynamodb:table"
	ResourceTypeSecretsManager ResourceType = "secretsmanager:secret"
	ResourceTypeLambdaFunction ResourceType = "lambda:function"
	ResourceTypeUnknown        ResourceType = "unknown"
)

// ResourceRef represents an identified AWS resource involved in an event.
type ResourceRef struct {
	ARN            string               `json:"arn,omitempty"`
	Type           ResourceType         `json:"type"`
	Name           string               `json:"name"`
	AccountID      string               `json:"account_id,omitempty"`
	Region         string               `json:"region,omitempty"`
	Classification *AssetClassification `json:"classification,omitempty"`
	Details        map[string]string    `json:"details,omitempty"`
}

func (r ResourceRef) DisplayString() string {
	if r.Classification != nil {
		return fmt.Sprintf("%s (%s / %s - %s)", r.Name, r.Type, r.Classification.AssetType, r.Classification.Sensitivity)
	}
	if r.Type != "" && r.Type != ResourceTypeUnknown {
		return fmt.Sprintf("%s (%s)", r.Name, r.Type)
	}
	return r.Name
}
