package model

import (
	"fmt"
	"strings"
)

// ActionRef captures the AWS API action and security-relevant behavioral flags.
type ActionRef struct {
	Normalized         string `json:"normalized"` // e.g. "s3:GetObject"
	Service            string `json:"service"`    // e.g. "s3"
	Verb               string `json:"verb"`       // e.g. "GetObject"
	IsPrivileged       bool   `json:"is_privileged"`
	IsDestructive      bool   `json:"is_destructive"`
	IsDataRead         bool   `json:"is_data_read"`
	IsDataWrite        bool   `json:"is_data_write"`
	IsCredentialAccess bool   `json:"is_credential_access"`
}

func (a ActionRef) String() string {
	if a.Normalized != "" {
		return a.Normalized
	}
	if a.Service != "" && a.Verb != "" {
		return fmt.Sprintf("%s:%s", a.Service, a.Verb)
	}
	return a.Verb
}

// NormalizeAction builds an ActionRef from service and verb, assigning operational flags.
func NormalizeAction(service, verb string) ActionRef {
	service = strings.ToLower(service)
	// Strip AWS domains if passed in, e.g. "s3.amazonaws.com" -> "s3"
	service = strings.TrimSuffix(service, ".amazonaws.com")
	norm := fmt.Sprintf("%s:%s", service, verb)

	ref := ActionRef{
		Normalized: norm,
		Service:    service,
		Verb:       verb,
	}

	switch norm {
	case "sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity", "sts:GetSessionToken", "sts:GetFederationToken":
		ref.IsCredentialAccess = true
		ref.IsPrivileged = true

	case "iam:CreateRole", "iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:CreatePolicy",
		"iam:CreateUser", "iam:CreateAccessKey", "iam:AttachUserPolicy", "iam:PutUserPolicy",
		"iam:UpdateAssumeRolePolicy":
		ref.IsPrivileged = true

	case "cloudtrail:DeleteTrail", "cloudtrail:StopLogging", "cloudtrail:UpdateTrail",
		"s3:DeleteBucket", "s3:DeleteBucketPolicy", "kms:ScheduleKeyDeletion", "kms:DisableKey":
		ref.IsDestructive = true
		ref.IsPrivileged = true

	case "s3:GetObject", "kms:Decrypt", "sqs:ReceiveMessage", "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "secretsmanager:GetSecretValue":
		ref.IsDataRead = true

	case "s3:PutObject", "s3:CopyObject", "s3:PostObject", "sqs:SendMessage", "dynamodb:PutItem", "dynamodb:UpdateItem":
		ref.IsDataWrite = true
	}

	return ref
}
