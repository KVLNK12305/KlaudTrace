package identity

import (
	"strings"
	"time"

	"github.com/klaudtrace/klaudtrace/internal/model"
)

// SessionRecord holds tracked STS session credentials and metadata.
type SessionRecord struct {
	AccessKeyID     string
	AssumedRoleARN  string
	RoleSessionName string
	AssumedRoleID   string
	RoleARN         string
	ParentIdentity  model.IdentityRef
	CreationTime    time.Time
	AssumeEventID   string
}

// Tracker correlates IAM identities, STS AssumeRole sessions, and downstream API calls.
type Tracker struct {
	sessionsByAccessKey map[string]*SessionRecord
	sessionsByRoleKey   map[string][]*SessionRecord // key: roleArn + "|" + sessionName
}

// NewTracker creates an initialized Tracker.
func NewTracker() *Tracker {
	return &Tracker{
		sessionsByAccessKey: make(map[string]*SessionRecord),
		sessionsByRoleKey:   make(map[string][]*SessionRecord),
	}
}

// RegisterAssumeRole registers an AssumeRole event and stores its issued session.
func (t *Tracker) RegisterAssumeRole(event *model.NormalizedEvent) *SessionRecord {
	if event == nil || event.Action.Normalized != "sts:AssumeRole" || event.IsError() {
		return nil
	}

	caller := event.Identity
	roleArn, _ := event.RequestParameters["roleArn"].(string)
	roleSessionName, _ := event.RequestParameters["roleSessionName"].(string)

	var accessKeyID string
	var assumedRoleARN string
	var assumedRoleID string

	if event.ResponseElements != nil {
		if creds, ok := event.ResponseElements["credentials"].(map[string]any); ok {
			accessKeyID, _ = creds["accessKeyId"].(string)
		}
		if assumedUser, ok := event.ResponseElements["assumedRoleUser"].(map[string]any); ok {
			assumedRoleARN, _ = assumedUser["arn"].(string)
			assumedRoleID, _ = assumedUser["assumedRoleId"].(string)
		}
	}

	rec := &SessionRecord{
		AccessKeyID:     accessKeyID,
		AssumedRoleARN:  assumedRoleARN,
		RoleSessionName: roleSessionName,
		AssumedRoleID:   assumedRoleID,
		RoleARN:         roleArn,
		ParentIdentity:  caller,
		CreationTime:    event.Timestamp,
		AssumeEventID:   event.ID,
	}

	if accessKeyID != "" {
		t.sessionsByAccessKey[accessKeyID] = rec
	}

	lookupKey := buildRoleLookupKey(roleArn, roleSessionName)
	t.sessionsByRoleKey[lookupKey] = append(t.sessionsByRoleKey[lookupKey], rec)

	return rec
}

// CorrelateEvent attempts to find the originating identity for an event's identity.
func (t *Tracker) CorrelateEvent(event *model.NormalizedEvent) {
	if event == nil {
		return
	}

	// Resolve parent for the caller identity if it is an AssumedRole
	if event.Identity.Type == model.IdentityTypeAssumedRole {
		matched := false

		// 1. First priority: match by exact temporary AccessKeyID
		if event.Identity.AccessKeyID != "" {
			if sess, exists := t.sessionsByAccessKey[event.Identity.AccessKeyID]; exists {
				event.Identity.ParentIdentity = cloneIdentity(sess.ParentIdentity)
				event.Identity.CorrelationConfidence = model.ConfidenceCorrelated
				matched = true
			}
		}

		// 2. Second priority: match by Role ARN/Name + Session Name created prior to this event
		if !matched {
			lookupKey := buildRoleLookupKey(event.Identity.SessionIssuerARN, event.Identity.SessionName)
			if lookupKey == "|" {
				lookupKey = buildRoleLookupKey(event.Identity.SessionIssuerName, event.Identity.SessionName)
			}
			candidates := t.sessionsByRoleKey[lookupKey]
			if len(candidates) == 0 && event.Identity.SessionIssuerName != "" {
				// try just role name
				candidates = t.sessionsByRoleKey[buildRoleLookupKey(event.Identity.SessionIssuerName, event.Identity.SessionName)]
			}

			if len(candidates) > 0 {
				var match *SessionRecord
				for i := len(candidates) - 1; i >= 0; i-- {
					cand := candidates[i]
					if !cand.CreationTime.After(event.Timestamp) {
						match = cand
						break
					}
				}
				if match != nil {
					event.Identity.ParentIdentity = cloneIdentity(match.ParentIdentity)
					event.Identity.CorrelationConfidence = model.ConfidenceCorrelated
					matched = true
				}
			}
		}

		if !matched {
			// Case 4 - Incomplete evidence. Do NOT force a false correlation!
			event.Identity.ParentIdentity = nil
			event.Identity.CorrelationConfidence = model.ConfidenceUndetermined
		}
	} else {
		event.Identity.CorrelationConfidence = model.ConfidenceObserved
	}

	// If this event was a successful AssumeRole, register the newly created session
	if event.Action.Normalized == "sts:AssumeRole" && !event.IsError() {
		t.RegisterAssumeRole(event)
	}
}

func cloneIdentity(id model.IdentityRef) *model.IdentityRef {
	cloned := id
	if id.ParentIdentity != nil {
		cloned.ParentIdentity = cloneIdentity(*id.ParentIdentity)
	}
	return &cloned
}

func buildRoleLookupKey(roleArn, sessionName string) string {
	return strings.ToLower(strings.TrimSpace(roleArn) + "|" + strings.TrimSpace(sessionName))
}
