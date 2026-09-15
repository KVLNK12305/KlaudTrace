package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/klaudtrace/klaudtrace/internal/model"
)

// Supported timestamp formats in AWS logs.
var timeFormats = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04:05",
}

// ParseTimestamp parses a timestamp string using supported formats.
func ParseTimestamp(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}
	for _, layout := range timeFormats {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse timestamp: %q", s)
}

// ParseRawEvent normalizes a single raw CloudTrail record.
func ParseRawEvent(raw *RawCloudTrailEvent, recordIndex int) (*model.NormalizedEvent, error) {
	if raw == nil {
		return nil, fmt.Errorf("nil raw event at index %d", recordIndex)
	}

	eventTime, _ := ParseTimestamp(raw.EventTime)

	// Ensure deterministic event ID
	eventID := strings.TrimSpace(raw.EventID)
	if eventID == "" {
		h := sha256.New()
		_, _ = fmt.Fprintf(h, "%s|%s|%s|%s|%d", raw.EventTime, raw.EventSource, raw.EventName, raw.SourceIPAddress, recordIndex)
		eventID = "gen-" + hex.EncodeToString(h.Sum(nil))[:16]
	}

	// Normalize identity
	identity := normalizeIdentity(raw.UserIdentity)

	// Normalize action
	action := model.NormalizeAction(raw.EventSource, raw.EventName)

	// Build evidence ref
	fieldEvidence := make(map[string]string)
	if raw.UserAgent != "" {
		fieldEvidence["userAgent"] = raw.UserAgent
	}
	if raw.RequestID != "" {
		fieldEvidence["requestID"] = raw.RequestID
	}
	if raw.RecipientAccountID != "" {
		fieldEvidence["recipientAccountId"] = raw.RecipientAccountID
	}

	sourceRef := model.EvidenceRef{
		EventID:       eventID,
		RecordIndex:   recordIndex,
		Timestamp:     eventTime,
		EventSource:   raw.EventSource,
		EventName:     raw.EventName,
		SourceIP:      raw.SourceIPAddress,
		FieldEvidence: fieldEvidence,
	}

	readOnly := false
	if raw.ReadOnly != nil {
		readOnly = *raw.ReadOnly
	} else {
		readOnly = action.IsDataRead
	}

	norm := &model.NormalizedEvent{
		ID:                 eventID,
		Timestamp:          eventTime,
		EventSource:        raw.EventSource,
		EventName:          raw.EventName,
		AWSExecutionRegion: raw.AWSRegion,
		SourceIPAddress:    raw.SourceIPAddress,
		UserAgent:          raw.UserAgent,
		Identity:           identity,
		Action:             action,
		RequestParameters:  raw.RequestParameters,
		ResponseElements:   raw.ResponseElements,
		ErrorCode:          raw.ErrorCode,
		ErrorMessage:       raw.ErrorMessage,
		ReadOnly:           readOnly,
		EventType:          raw.EventType,
		SourceRef:          sourceRef,
		RawJSON:            raw.Raw,
	}

	return norm, nil
}

func normalizeIdentity(raw *RawUserIdentity) model.IdentityRef {
	if raw == nil {
		return model.IdentityRef{
			Type:                  model.IdentityTypeUnknown,
			CorrelationConfidence: model.ConfidenceUndetermined,
		}
	}

	id := model.IdentityRef{
		PrincipalID: raw.PrincipalID,
		ARN:         raw.ARN,
		AccountID:   raw.AccountID,
		UserName:    raw.UserName,
		AccessKeyID: raw.AccessKeyID,
	}

	switch strings.ToLower(raw.Type) {
	case "iamuser":
		id.Type = model.IdentityTypeIAMUser
	case "assumedrole":
		id.Type = model.IdentityTypeAssumedRole
		extractAssumedRoleDetails(&id, raw)
	case "role":
		id.Type = model.IdentityTypeRole
	case "root":
		id.Type = model.IdentityTypeRoot
	case "federateduser":
		id.Type = model.IdentityTypeFederatedUser
	case "awsservice":
		id.Type = model.IdentityTypeAWSService
		if id.UserName == "" && raw.InvokedBy != "" {
			id.UserName = raw.InvokedBy
		}
	default:
		if raw.InvokedBy != "" {
			id.Type = model.IdentityTypeAWSService
			id.UserName = raw.InvokedBy
		} else {
			id.Type = model.IdentityTypeUnknown
		}
	}

	return id
}

func extractAssumedRoleDetails(id *model.IdentityRef, raw *RawUserIdentity) {
	// e.g. arn:aws:sts::123456789012:assumed-role/PaymentServiceRole/DevJoe
	if id.ARN != "" && strings.Contains(id.ARN, ":assumed-role/") {
		parts := strings.Split(id.ARN, ":assumed-role/")
		if len(parts) == 2 {
			subParts := strings.Split(parts[1], "/")
			if len(subParts) >= 2 {
				id.SessionIssuerName = subParts[0]
				id.SessionName = strings.Join(subParts[1:], "/")
			} else if len(subParts) == 1 {
				id.SessionIssuerName = subParts[0]
			}
		}
	}

	// Check sessionContext
	if raw.SessionContext != nil && raw.SessionContext.SessionIssuer != nil {
		issuer := raw.SessionContext.SessionIssuer
		if id.SessionIssuerName == "" {
			id.SessionIssuerName = issuer.UserName
		}
		if id.SessionIssuerARN == "" {
			id.SessionIssuerARN = issuer.ARN
		}
		if id.AccountID == "" {
			id.AccountID = issuer.AccountID
		}
	}

	// Principal ID in assumed-role is typically AROAXXXXX:session-name
	if id.SessionName == "" && strings.Contains(raw.PrincipalID, ":") {
		parts := strings.Split(raw.PrincipalID, ":")
		if len(parts) == 2 {
			id.AssumedRoleID = parts[0]
			id.SessionName = parts[1]
		}
	}
}
