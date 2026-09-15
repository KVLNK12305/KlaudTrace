package analysis

import (
	"fmt"

	"github.com/klaudtrace/klaudtrace/internal/correlation"
	"github.com/klaudtrace/klaudtrace/internal/model"
)

// ReconstructPaths builds observed activity and attack paths from correlated session groups.
func ReconstructPaths(groups []*correlation.SessionGroup) []model.ObservedPath {
	var paths []model.ObservedPath

	for idx, group := range groups {
		if len(group.Events) == 0 {
			continue
		}

		// Filter for security-relevant or meaningful events (read/write/privileged/credential)
		var relevantEvents []*model.NormalizedEvent
		for _, e := range group.Events {
			if isMeaningfulEvent(e) {
				relevantEvents = append(relevantEvents, e)
			}
		}

		if len(relevantEvents) == 0 {
			continue
		}

		path := buildPathForGroup(group, relevantEvents, idx+1)
		paths = append(paths, path)
	}

	return paths
}

func isMeaningfulEvent(e *model.NormalizedEvent) bool {
	if e.Action.IsPrivileged || e.Action.IsDestructive || e.Action.IsCredentialAccess {
		return true
	}
	if e.Action.IsDataRead || e.Action.IsDataWrite {
		// Include if resources have classifications or if it's S3/KMS/IAM/CloudTrail
		for _, r := range e.Resources {
			if r.Classification != nil {
				return true
			}
		}
		if e.Action.Service == "s3" || e.Action.Service == "kms" {
			return true
		}
	}
	return false
}

func buildPathForGroup(group *correlation.SessionGroup, events []*model.NormalizedEvent, pathIndex int) model.ObservedPath {
	var nodes []model.ObservedPathNode
	var evidenceList []model.EvidenceRef
	pathConfidence := model.ConfidenceObserved

	firstEvt := events[0]
	ident := firstEvt.Identity

	// 1. Reconstruct identity hierarchy (Root -> AssumeRole -> Session)
	if ident.ParentIdentity != nil {
		pathConfidence = model.ConfidenceCorrelated
		// Root identity
		nodes = append(nodes, model.ObservedPathNode{
			Type:       model.PathNodeIdentity,
			Label:      ident.ParentIdentity.DisplayName(),
			Detail:     ident.ParentIdentity.QualifiedName(),
			Confidence: model.ConfidenceObserved,
		})

		// AssumeRole action
		roleLabel := ident.SessionIssuerName
		if roleLabel == "" {
			roleLabel = "AssumedRole"
		}
		nodes = append(nodes, model.ObservedPathNode{
			Type:       model.PathNodeRole,
			Label:      roleLabel,
			Detail:     fmt.Sprintf("AssumeRole -> %s", roleLabel),
			Confidence: model.ConfidenceCorrelated,
		})

		// Assumed session
		nodes = append(nodes, model.ObservedPathNode{
			Type:       model.PathNodeSession,
			Label:      ident.DisplayName(),
			Detail:     fmt.Sprintf("Session: %s", ident.SessionName),
			Confidence: model.ConfidenceCorrelated,
		})
	} else if ident.Type == model.IdentityTypeAssumedRole {
		// Incomplete evidence / unobserved assumption
		nodes = append(nodes, model.ObservedPathNode{
			Type:       model.PathNodeSession,
			Label:      ident.DisplayName(),
			Detail:     "Assumed role session (origin undetermined in provided logs)",
			Confidence: model.ConfidenceUndetermined,
		})
	} else {
		// Direct identity
		nodes = append(nodes, model.ObservedPathNode{
			Type:       model.PathNodeIdentity,
			Label:      ident.DisplayName(),
			Detail:     ident.QualifiedName(),
			Confidence: model.ConfidenceObserved,
		})
	}

	// 2. Add sequential actions and resources
	for _, e := range events {
		evidenceList = append(evidenceList, e.SourceRef)

		// Action node
		actionLabel := e.Action.Normalized
		if actionLabel == "" {
			actionLabel = e.EventName
		}
		nodes = append(nodes, model.ObservedPathNode{
			Type:        model.PathNodeAction,
			Label:       actionLabel,
			Confidence:  model.ConfidenceObserved,
			EvidenceRef: &e.SourceRef,
		})

		// Resource nodes
		for _, r := range e.Resources {
			resLabel := r.Name
			detail := string(r.Type)
			if r.Classification != nil {
				detail = fmt.Sprintf("%s [%s - %s]", r.Type, r.Classification.AssetType, r.Classification.Sensitivity)
			}
			nodes = append(nodes, model.ObservedPathNode{
				Type:        model.PathNodeResource,
				Label:       resLabel,
				Detail:      detail,
				Confidence:  model.ConfidenceObserved,
				EvidenceRef: &e.SourceRef,
			})
		}
	}

	title := fmt.Sprintf("Observed Path #%d: %s activity", pathIndex, ident.DisplayName())
	summary := fmt.Sprintf("Identity %s executed %d observed actions across %d resources.",
		ident.DisplayName(), len(events), len(evidenceList))

	return model.ObservedPath{
		ID:         fmt.Sprintf("path-%d", pathIndex),
		Title:      title,
		Nodes:      nodes,
		Confidence: pathConfidence,
		Evidence:   evidenceList,
		Summary:    summary,
	}
}
