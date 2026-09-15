package correlation

import (
	"strings"

	"github.com/klaudtrace/klaudtrace/internal/classification"
	"github.com/klaudtrace/klaudtrace/internal/identity"
	"github.com/klaudtrace/klaudtrace/internal/model"
	"github.com/klaudtrace/klaudtrace/internal/resource"
	"github.com/klaudtrace/klaudtrace/internal/timeline"
)

// SessionGroup groups events belonging to the same principal or session lineage.
type SessionGroup struct {
	SessionKey string
	Identity   model.IdentityRef
	Events     []*model.NormalizedEvent
}

// CorrelatePipeline processes raw ingested events through chronological sorting,
// resource extraction, fintech classification, and identity session tracking.
func CorrelatePipeline(rawEvents []*model.NormalizedEvent, classifier *classification.Classifier) ([]*model.NormalizedEvent, *identity.Tracker) {
	if classifier == nil {
		classifier = classification.New()
	}

	// Step 1: Chronological sort
	sorted := timeline.SortEvents(rawEvents)

	// Step 2: Initialize tracker
	tracker := identity.NewTracker()

	// Step 3: Extract resources, classify, and track identities in order
	for _, event := range sorted {
		// Extract resources if not already populated
		if len(event.Resources) == 0 {
			event.Resources = resource.ExtractResources(nil, event)
		}
		classifier.ClassifyAll(event.Resources)

		// Correlate identity with session lineage
		tracker.CorrelateEvent(event)
	}

	return sorted, tracker
}

// GroupBySession clusters events into logical session groups.
func GroupBySession(events []*model.NormalizedEvent) []*SessionGroup {
	groupMap := make(map[string]*SessionGroup)
	var orderedKeys []string

	for _, e := range events {
		key := deriveSessionKey(e)
		group, exists := groupMap[key]
		if !exists {
			group = &SessionGroup{
				SessionKey: key,
				Identity:   e.Identity,
				Events:     make([]*model.NormalizedEvent, 0),
			}
			groupMap[key] = group
			orderedKeys = append(orderedKeys, key)
		}
		group.Events = append(group.Events, e)
	}

	result := make([]*SessionGroup, 0, len(orderedKeys))
	for _, k := range orderedKeys {
		result = append(result, groupMap[k])
	}
	return result
}

func deriveSessionKey(e *model.NormalizedEvent) string {
	if e.Identity.AccessKeyID != "" {
		return e.Identity.AccessKeyID
	}
	if e.Identity.Type == model.IdentityTypeAssumedRole {
		return strings.ToLower(e.Identity.SessionIssuerName + "/" + e.Identity.SessionName)
	}
	if e.Identity.ARN != "" {
		return strings.ToLower(e.Identity.ARN)
	}
	if e.Identity.UserName != "" {
		return strings.ToLower(e.Identity.UserName)
	}
	return strings.ToLower(string(e.Identity.Type) + "/" + e.SourceIPAddress)
}
