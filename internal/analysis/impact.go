package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/klaudtrace/klaudtrace/internal/correlation"
	"github.com/klaudtrace/klaudtrace/internal/model"
	"github.com/klaudtrace/klaudtrace/internal/timeline"
)

// EvaluateImpact generates concrete, evidence-backed findings from correlated sessions.
func EvaluateImpact(events []*model.NormalizedEvent, paths []model.ObservedPath, groups []*correlation.SessionGroup) []model.ImpactFinding {
	var findings []model.ImpactFinding
	findingIndex := 1

	// 1. Check for sensitive data reads (S3)
	var sensitiveReadEvents []*model.NormalizedEvent
	var sensitiveAssets []model.ResourceRef
	assetSeen := make(map[string]bool)

	for _, e := range events {
		if e.Action.Service == "s3" && e.Action.IsDataRead && !e.IsError() {
			for _, r := range e.Resources {
				if r.Classification != nil && (r.Classification.Sensitivity == model.SensitivityCritical || r.Classification.Sensitivity == model.SensitivityHigh) {
					sensitiveReadEvents = append(sensitiveReadEvents, e)
					if !assetSeen[r.Name] {
						assetSeen[r.Name] = true
						sensitiveAssets = append(sensitiveAssets, r)
					}
				}
			}
		}
	}

	if len(sensitiveReadEvents) > 0 {
		var evRefs []model.EvidenceRef
		var idRefs []model.IdentityRef
		idSeen := make(map[string]bool)

		for _, e := range sensitiveReadEvents {
			evRefs = append(evRefs, e.SourceRef)
			idName := e.Identity.DisplayName()
			if !idSeen[idName] {
				idSeen[idName] = true
				idRefs = append(idRefs, e.Identity)
			}
		}

		assetNames := make([]string, 0, len(sensitiveAssets))
		for _, a := range sensitiveAssets {
			assetNames = append(assetNames, fmt.Sprintf("%s (%s / %s)", a.Name, a.Classification.AssetType, a.Classification.Sensitivity))
		}

		findings = append(findings, model.ImpactFinding{
			ID:          fmt.Sprintf("impact-%d", findingIndex),
			Title:       "Observed Access to Sensitive Fintech Data",
			Description: fmt.Sprintf("CloudTrail evidence confirms access to sensitive resources: %s.", strings.Join(assetNames, ", ")),
			Severity:    model.SensitivityCritical,
			Confidence:  model.ConfidenceObserved,
			AffectedResources: sensitiveAssets,
			Identities:        idRefs,
			Evidence:          evRefs,
			EvidenceBasis:     "Direct s3:GetObject API calls recorded with success response.",
			Limitations:       "The supplied CloudTrail evidence establishes resource access. It does not by itself establish data exfiltration beyond the AWS environment.",
		})
		findingIndex++
	}

	// 2. Check for KMS Decryption on payment/cryptographic keys
	var kmsEvents []*model.NormalizedEvent
	var kmsKeys []model.ResourceRef
	kmsSeen := make(map[string]bool)

	for _, e := range events {
		if e.Action.Normalized == "kms:Decrypt" && !e.IsError() {
			kmsEvents = append(kmsEvents, e)
			for _, r := range e.Resources {
				if !kmsSeen[r.Name] {
					kmsSeen[r.Name] = true
					kmsKeys = append(kmsKeys, r)
				}
			}
		}
	}

	if len(kmsEvents) > 0 {
		var evRefs []model.EvidenceRef
		var idRefs []model.IdentityRef
		idSeen := make(map[string]bool)

		for _, e := range kmsEvents {
			evRefs = append(evRefs, e.SourceRef)
			idName := e.Identity.DisplayName()
			if !idSeen[idName] {
				idSeen[idName] = true
				idRefs = append(idRefs, e.Identity)
			}
		}

		findings = append(findings, model.ImpactFinding{
			ID:                fmt.Sprintf("impact-%d", findingIndex),
			Title:             "Observed Cryptographic Decryption of Sensitive Keys",
			Description:       fmt.Sprintf("CloudTrail evidence records %d kms:Decrypt operations involving cryptographic keys.", len(kmsEvents)),
			Severity:          model.SensitivityCritical,
			Confidence:        model.ConfidenceObserved,
			AffectedResources: kmsKeys,
			Identities:        idRefs,
			Evidence:          evRefs,
			EvidenceBasis:     "Direct kms:Decrypt API call successfully processed.",
			Limitations:       "Evidence confirms decryption was performed; decrypted plain-text content is not stored in CloudTrail logs.",
		})
		findingIndex++
	}

	// 3. Check for Administrative Privilege Escalation & Persistence
	var iamMutationEvents []*model.NormalizedEvent
	for _, e := range events {
		if (e.Action.Normalized == "iam:CreateRole" || e.Action.Normalized == "iam:PutRolePolicy" || e.Action.Normalized == "iam:AttachRolePolicy" || e.Action.Normalized == "iam:CreateUser" || e.Action.Normalized == "iam:CreateAccessKey") && !e.IsError() {
			iamMutationEvents = append(iamMutationEvents, e)
		}
	}

	if len(iamMutationEvents) > 0 {
		var evRefs []model.EvidenceRef
		var idRefs []model.IdentityRef
		var resList []model.ResourceRef
		idSeen := make(map[string]bool)

		for _, e := range iamMutationEvents {
			evRefs = append(evRefs, e.SourceRef)
			idName := e.Identity.DisplayName()
			if !idSeen[idName] {
				idSeen[idName] = true
				idRefs = append(idRefs, e.Identity)
			}
			resList = append(resList, e.Resources...)
		}

		findings = append(findings, model.ImpactFinding{
			ID:                fmt.Sprintf("impact-%d", findingIndex),
			Title:             "Observed Administrative Role / Policy Creation",
			Description:       "IAM configuration changes creating or escalating roles and policies were observed in the event stream.",
			Severity:          model.SensitivityHigh,
			Confidence:        model.ConfidenceObserved,
			AffectedResources: resList,
			Identities:        idRefs,
			Evidence:          evRefs,
			EvidenceBasis:     "Direct IAM administrative API calls recorded with success.",
			Limitations:       "Activity is consistent with administrative configuration changes or persistence; compromise cannot be asserted without credential authorization context.",
		})
		findingIndex++
	}

	// 4. Check for Destructive / Evasion Actions (e.g. DeleteTrail)
	var destructiveEvents []*model.NormalizedEvent
	for _, e := range events {
		if e.Action.IsDestructive && !e.IsError() {
			destructiveEvents = append(destructiveEvents, e)
		}
	}

	if len(destructiveEvents) > 0 {
		var evRefs []model.EvidenceRef
		var idRefs []model.IdentityRef
		var resList []model.ResourceRef
		idSeen := make(map[string]bool)

		for _, e := range destructiveEvents {
			evRefs = append(evRefs, e.SourceRef)
			idName := e.Identity.DisplayName()
			if !idSeen[idName] {
				idSeen[idName] = true
				idRefs = append(idRefs, e.Identity)
			}
			resList = append(resList, e.Resources...)
		}

		findings = append(findings, model.ImpactFinding{
			ID:                fmt.Sprintf("impact-%d", findingIndex),
			Title:             "Observed Audit Trail / Resource Deletion",
			Description:       "Destructive operations impacting audit visibility or resources were observed.",
			Severity:          model.SensitivityCritical,
			Confidence:        model.ConfidenceObserved,
			AffectedResources: resList,
			Identities:        idRefs,
			Evidence:          evRefs,
			EvidenceBasis:     "Destructive API call recorded with success.",
			Limitations:       "Logs establish that trail/resource was deleted; subsequent unlogged activity may have occurred after logging ceased.",
		})
		findingIndex++
	}

	// 5. Check for Cross-Bucket Data Movement
	for _, group := range groups {
		var readBuckets []string
		var writeBuckets []string
		var movementEvidence []model.EvidenceRef

		for _, e := range group.Events {
			if e.IsError() {
				continue
			}
			switch e.Action.Normalized {
			case "s3:GetObject":
				for _, r := range e.Resources {
					bucket := extractBucketFromResource(r)
					if bucket != "" {
						readBuckets = append(readBuckets, bucket)
						movementEvidence = append(movementEvidence, e.SourceRef)
					}
				}
			case "s3:PutObject":
				for _, r := range e.Resources {
					bucket := extractBucketFromResource(r)
					if bucket != "" {
						writeBuckets = append(writeBuckets, bucket)
						movementEvidence = append(movementEvidence, e.SourceRef)
					}
				}
			}
		}

		// Detect distinct source and destination bucket in same session
		if len(readBuckets) > 0 && len(writeBuckets) > 0 {
			diffBucket := false
			for _, rb := range readBuckets {
				for _, wb := range writeBuckets {
					if rb != wb {
						diffBucket = true
						break
					}
				}
			}

			if diffBucket {
				findings = append(findings, model.ImpactFinding{
					ID:          fmt.Sprintf("impact-%d", findingIndex),
					Title:       "Observed Cross-Bucket Data Movement",
					Description: fmt.Sprintf("Identity %s performed s3:GetObject followed by s3:PutObject across distinct S3 buckets within the same session.", group.Identity.DisplayName()),
					Severity:    model.SensitivityHigh,
					Confidence:  model.ConfidenceCorrelated,
					Identities:  []model.IdentityRef{group.Identity},
					Evidence:    movementEvidence,
					EvidenceBasis: "Paired s3:GetObject and s3:PutObject API calls executed within the same session lineage.",
					Limitations:   "Cross-bucket data movement is evidenced. External network exfiltration is not established from CloudTrail alone.",
				})
				findingIndex++
			}
		}
	}

	return findings
}

func extractBucketFromResource(r model.ResourceRef) string {
	if r.Type == model.ResourceTypeS3Bucket {
		return r.Name
	}
	if r.Details != nil && r.Details["bucket"] != "" {
		return r.Details["bucket"]
	}
	if strings.HasPrefix(r.Name, "arn:aws:s3:::") {
		trimmed := strings.TrimPrefix(r.Name, "arn:aws:s3:::")
		parts := strings.Split(trimmed, "/")
		return parts[0]
	}
	parts := strings.Split(r.Name, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// GenerateIncidentSummary builds the final deterministic incident summary.
func GenerateIncidentSummary(events []*model.NormalizedEvent, paths []model.ObservedPath, findings []model.ImpactFinding) *model.IncidentSummary {
	start, end := timeline.TimeWindow(events)

	// Collect unique identities deterministically
	identityMap := make(map[string]model.IdentityRef)
	for _, e := range events {
		name := e.Identity.DisplayName()
		if _, exists := identityMap[name]; !exists {
			identityMap[name] = e.Identity
		}
		if e.Identity.ParentIdentity != nil {
			parentName := e.Identity.ParentIdentity.DisplayName()
			if _, exists := identityMap[parentName]; !exists {
				identityMap[parentName] = *e.Identity.ParentIdentity
			}
		}
	}

	var identities []model.IdentityRef
	for _, id := range identityMap {
		identities = append(identities, id)
	}
	sort.Slice(identities, func(i, j int) bool {
		return identities[i].DisplayName() < identities[j].DisplayName()
	})

	// Collect unique affected classified assets
	assetMap := make(map[string]model.ResourceRef)
	for _, e := range events {
		for _, r := range e.Resources {
			if r.Classification != nil {
				key := r.Name
				if _, exists := assetMap[key]; !exists {
					assetMap[key] = r
				}
			}
		}
	}

	var affectedAssets []model.ResourceRef
	for _, a := range assetMap {
		affectedAssets = append(affectedAssets, a)
	}
	sort.Slice(affectedAssets, func(i, j int) bool {
		return affectedAssets[i].Name < affectedAssets[j].Name
	})

	errorCount := 0
	for _, e := range events {
		if e.IsError() {
			errorCount++
		}
	}

	// Generate conservative assessment statement
	statement := generateAssessmentStatement(identities, affectedAssets, findings)

	return &model.IncidentSummary{
		TimeWindowStart:     start,
		TimeWindowEnd:       end,
		TotalEvents:         len(events),
		ParsedEvents:        len(events),
		ErrorEvents:         errorCount,
		Identities:          identities,
		AffectedAssets:      affectedAssets,
		Paths:               paths,
		Findings:            findings,
		AssessmentStatement: statement,
	}
}

func generateAssessmentStatement(identities []model.IdentityRef, assets []model.ResourceRef, findings []model.ImpactFinding) string {
	if len(findings) == 0 {
		return "Activity is consistent with routine authorized operations. No sensitive resource access, privilege escalation, or destructive actions were established by the supplied evidence."
	}

	var parts []string
	var idNames []string
	for _, id := range identities {
		idNames = append(idNames, id.DisplayName())
	}

	parts = append(parts, fmt.Sprintf("CloudTrail evidence establishes activity involving identities [%s].", strings.Join(idNames, ", ")))

	if len(assets) > 0 {
		var assetDetails []string
		for _, a := range assets {
			assetDetails = append(assetDetails, fmt.Sprintf("%s (%s / %s)", a.Name, a.Classification.AssetType, a.Classification.Sensitivity))
		}
		parts = append(parts, fmt.Sprintf("Access or modification to classified resources was observed: [%s].", strings.Join(assetDetails, ", ")))
	}

	parts = append(parts, "The supplied CloudTrail evidence by itself does not establish that data was exfiltrated beyond the AWS environment.")

	return strings.Join(parts, " ")
}
