package model

import (
	"fmt"
	"strings"
)

// IdentityType categorizes the caller identity.
type IdentityType string

const (
	IdentityTypeIAMUser       IdentityType = "IAMUser"
	IdentityTypeAssumedRole   IdentityType = "AssumedRole"
	IdentityTypeRole          IdentityType = "Role"
	IdentityTypeRoot          IdentityType = "Root"
	IdentityTypeFederatedUser IdentityType = "FederatedUser"
	IdentityTypeAWSService    IdentityType = "AWSService"
	IdentityTypeUnknown       IdentityType = "Unknown"
)

// IdentityRef describes an AWS principal or session.
type IdentityRef struct {
	Type                  IdentityType    `json:"type"`
	PrincipalID           string          `json:"principal_id,omitempty"`
	ARN                   string          `json:"arn,omitempty"`
	AccountID             string          `json:"account_id,omitempty"`
	UserName              string          `json:"user_name,omitempty"`
	SessionName           string          `json:"session_name,omitempty"`
	SessionIssuerARN      string          `json:"session_issuer_arn,omitempty"`
	SessionIssuerName     string          `json:"session_issuer_name,omitempty"`
	AccessKeyID           string          `json:"access_key_id,omitempty"`
	AssumedRoleID         string          `json:"assumed_role_id,omitempty"`
	ParentIdentity        *IdentityRef    `json:"parent_identity,omitempty"`
	CorrelationConfidence ConfidenceLevel `json:"correlation_confidence,omitempty"`
}

// DisplayName provides a clean, concise name for reporting and diagrams.
func (id IdentityRef) DisplayName() string {
	if id.Type == IdentityTypeAssumedRole {
		if id.SessionIssuerName != "" && id.SessionName != "" {
			return fmt.Sprintf("%s/%s", id.SessionIssuerName, id.SessionName)
		}
		if id.SessionIssuerName != "" {
			return id.SessionIssuerName
		}
	}
	if id.UserName != "" {
		return id.UserName
	}
	if id.SessionName != "" {
		return id.SessionName
	}
	if id.ARN != "" {
		parts := strings.Split(id.ARN, "/")
		if len(parts) > 1 {
			return parts[len(parts)-1]
		}
		colonParts := strings.Split(id.ARN, ":")
		if len(colonParts) > 0 {
			return colonParts[len(colonParts)-1]
		}
		return id.ARN
	}
	if id.PrincipalID != "" {
		return id.PrincipalID
	}
	return string(id.Type)
}

// QualifiedName provides a disambiguated string representation.
func (id IdentityRef) QualifiedName() string {
	return fmt.Sprintf("%s:%s", id.Type, id.DisplayName())
}
