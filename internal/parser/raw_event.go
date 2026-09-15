package parser

import "encoding/json"

// RawUserIdentity maps CloudTrail's userIdentity structure.
type RawUserIdentity struct {
	Type           string             `json:"type"`
	PrincipalID    string             `json:"principalId"`
	ARN            string             `json:"arn"`
	AccountID      string             `json:"accountId"`
	AccessKeyID    string             `json:"accessKeyId"`
	UserName       string             `json:"userName"`
	SessionContext *RawSessionContext `json:"sessionContext,omitempty"`
	InvokedBy      string             `json:"invokedBy,omitempty"`
}

// RawSessionContext maps CloudTrail sessionContext.
type RawSessionContext struct {
	SessionIssuer *RawSessionIssuer `json:"sessionIssuer,omitempty"`
	Attributes    map[string]any    `json:"attributes,omitempty"`
}

// RawSessionIssuer maps sessionIssuer within sessionContext.
type RawSessionIssuer struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	ARN         string `json:"arn"`
	AccountID   string `json:"accountId"`
	UserName    string `json:"userName"`
}

// RawResource maps entries in CloudTrail's resources array.
type RawResource struct {
	Type      string `json:"type"`
	ARN       string `json:"ARN"`
	AccountID string `json:"accountId,omitempty"`
}

// RawCloudTrailEvent captures the raw CloudTrail JSON fields while preserving dynamic payloads.
type RawCloudTrailEvent struct {
	EventVersion       string                 `json:"eventVersion"`
	UserIdentity       *RawUserIdentity       `json:"userIdentity,omitempty"`
	EventTime          string                 `json:"eventTime"`
	EventSource        string                 `json:"eventSource"`
	EventName          string                 `json:"eventName"`
	AWSRegion          string                 `json:"awsRegion"`
	SourceIPAddress    string                 `json:"sourceIPAddress"`
	UserAgent          string                 `json:"userAgent"`
	ErrorCode          string                 `json:"errorCode,omitempty"`
	ErrorMessage       string                 `json:"errorMessage,omitempty"`
	RequestParameters  map[string]any         `json:"requestParameters,omitempty"`
	ResponseElements   map[string]any         `json:"responseElements,omitempty"`
	Resources          []RawResource          `json:"resources,omitempty"`
	RequestID          string                 `json:"requestID,omitempty"`
	EventID            string                 `json:"eventID"`
	EventType          string                 `json:"eventType"`
	ReadOnly           *bool                  `json:"readOnly,omitempty"`
	RecipientAccountID string                 `json:"recipientAccountId,omitempty"`
	SharedEventID      string                 `json:"sharedEventID,omitempty"`

	// Raw is preserved for 100% evidence fidelity
	Raw json.RawMessage `json:"-"`
}
