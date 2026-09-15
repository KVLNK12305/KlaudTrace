package model

import (
	"time"
)

// ImpactFinding captures a concrete, evidence-backed security finding.
type ImpactFinding struct {
	ID                string           `json:"id"`
	Title             string           `json:"title"`
	Description       string           `json:"description"`
	Severity          SensitivityLevel `json:"severity"`
	Confidence        ConfidenceLevel  `json:"confidence"`
	AffectedResources []ResourceRef    `json:"affected_resources,omitempty"`
	Identities        []IdentityRef    `json:"identities,omitempty"`
	Evidence          []EvidenceRef    `json:"evidence"`
	EvidenceBasis     string           `json:"evidence_basis"`
	Limitations       string           `json:"limitations"` // Explicitly states what is NOT established
}

// PathNodeType defines the category of a node in an observed activity path.
type PathNodeType string

const (
	PathNodeIdentity PathNodeType = "Identity"
	PathNodeRole     PathNodeType = "Role"
	PathNodeSession  PathNodeType = "Session"
	PathNodeAction   PathNodeType = "Action"
	PathNodeResource PathNodeType = "Resource"
)

// ObservedPathNode represents a single step in a reconstructed chain of activity.
type ObservedPathNode struct {
	Type        PathNodeType    `json:"type"`
	Label       string          `json:"label"`
	Detail      string          `json:"detail,omitempty"`
	Confidence  ConfidenceLevel `json:"confidence"`
	EvidenceRef *EvidenceRef    `json:"evidence_ref,omitempty"`
}

// ObservedPath represents an evidenced sequence of Identity -> Action -> Resource.
type ObservedPath struct {
	ID         string             `json:"id"`
	Title      string             `json:"title"`
	Nodes      []ObservedPathNode `json:"nodes"`
	Confidence ConfidenceLevel    `json:"confidence"`
	Evidence   []EvidenceRef      `json:"evidence"`
	Summary    string             `json:"summary"`
}

// IncidentSummary contains the reconstructed analysis of the ingested log set.
type IncidentSummary struct {
	TimeWindowStart     time.Time        `json:"time_window_start"`
	TimeWindowEnd       time.Time        `json:"time_window_end"`
	TotalEvents         int              `json:"total_events"`
	ParsedEvents        int              `json:"parsed_events"`
	ErrorEvents         int              `json:"error_events"`
	Identities          []IdentityRef    `json:"identities"`
	AffectedAssets      []ResourceRef    `json:"affected_assets"`
	Paths               []ObservedPath   `json:"paths"`
	Findings            []ImpactFinding  `json:"findings"`
	AssessmentStatement string           `json:"assessment_statement"`
}
