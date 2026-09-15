package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/klaudtrace/klaudtrace/internal/model"
)

// RenderMarkdown formats the incident summary into an executive-ready GitHub-flavored Markdown report.
func RenderMarkdown(summary *model.IncidentSummary) string {
	var b strings.Builder

	b.WriteString("# KlaudTrace Incident Reconstruction Report\n\n")

	// Overview
	b.WriteString("## Executive Summary\n\n")
	b.WriteString(fmt.Sprintf("> **Assessment:** %s\n\n", summary.AssessmentStatement))

	b.WriteString("| Metric | Value |\n")
	b.WriteString("| :--- | :--- |\n")
	if !summary.TimeWindowStart.IsZero() {
		dur := summary.TimeWindowEnd.Sub(summary.TimeWindowStart).Round(time.Second)
		b.WriteString(fmt.Sprintf("| **Time Window** | `%s` to `%s` (%s) |\n",
			summary.TimeWindowStart.UTC().Format(time.RFC3339),
			summary.TimeWindowEnd.UTC().Format(time.RFC3339),
			dur))
	}
	b.WriteString(fmt.Sprintf("| **Total Log Records** | `%d` |\n", summary.TotalEvents))
	b.WriteString(fmt.Sprintf("| **Error / Denied Events** | `%d` |\n", summary.ErrorEvents))
	b.WriteString(fmt.Sprintf("| **Identities Tracked** | `%d` |\n", len(summary.Identities)))
	b.WriteString(fmt.Sprintf("| **Classified Assets Affected** | `%d` |\n\n", len(summary.AffectedAssets)))

	// Identities Table
	b.WriteString("## Identified Principals & Sessions\n\n")
	if len(summary.Identities) == 0 {
		b.WriteString("_No identities identified in evidence._\n\n")
	} else {
		b.WriteString("| Principal / Session | Type | Account ID | Session Issuer | Lineage Confidence |\n")
		b.WriteString("| :--- | :--- | :--- | :--- | :--- |\n")
		for _, id := range summary.Identities {
			issuer := "-"
			if id.SessionIssuerName != "" {
				issuer = id.SessionIssuerName
			}
			conf := id.CorrelationConfidence
			if conf == "" {
				conf = model.ConfidenceObserved
			}
			b.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | `%s` | **%s** |\n",
				id.DisplayName(), id.Type, id.AccountID, issuer, conf))
		}
		b.WriteString("\n")
	}

	// Affected Assets
	b.WriteString("## Affected Classified Assets\n\n")
	if len(summary.AffectedAssets) == 0 {
		b.WriteString("_No classified sensitive assets identified._\n\n")
	} else {
		b.WriteString("| Resource | Type | Domain | Asset Type | Sensitivity |\n")
		b.WriteString("| :--- | :--- | :--- | :--- | :--- |\n")
		for _, a := range summary.AffectedAssets {
			domain := "-"
			assetType := "-"
			sens := "-"
			if a.Classification != nil {
				domain = a.Classification.Domain
				assetType = a.Classification.AssetType
				sens = string(a.Classification.Sensitivity)
			}
			b.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | `%s` | **%s** |\n",
				a.Name, a.Type, domain, assetType, sens))
		}
		b.WriteString("\n")
	}

	// Observed Attack Paths with Mermaid Flowchart
	b.WriteString("## Observed Activity & Attack Paths\n\n")
	if len(summary.Paths) == 0 {
		b.WriteString("_No multi-step activity paths established._\n\n")
	} else {
		for _, p := range summary.Paths {
			b.WriteString(fmt.Sprintf("### %s\n\n", p.Title))
			b.WriteString(fmt.Sprintf("**Confidence Level:** `%s`  \n", p.Confidence))
			b.WriteString(fmt.Sprintf("**Summary:** %s\n\n", p.Summary))

			// Mermaid diagram
			b.WriteString("```mermaid\nflowchart TD\n")
			for i, node := range p.Nodes {
				nodeID := fmt.Sprintf("N%d_%s", i, sanitizeForMermaid(node.Label))
				cleanLabel := strings.ReplaceAll(node.Label, `"`, `'`)
				if node.Detail != "" {
					cleanDetail := strings.ReplaceAll(node.Detail, `"`, `'`)
					b.WriteString(fmt.Sprintf("    %s[\"%s<br/><small>%s</small>\"]\n", nodeID, cleanLabel, cleanDetail))
				} else {
					b.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", nodeID, cleanLabel))
				}
				if i > 0 {
					prevID := fmt.Sprintf("N%d_%s", i-1, sanitizeForMermaid(p.Nodes[i-1].Label))
					b.WriteString(fmt.Sprintf("    %s --> %s\n", prevID, nodeID))
				}
			}
			b.WriteString("```\n\n")
		}
	}

	// Findings
	b.WriteString("## Impact Findings\n\n")
	if len(summary.Findings) == 0 {
		b.WriteString("_No high-severity impact findings triggered._\n\n")
	} else {
		for _, f := range summary.Findings {
			b.WriteString(fmt.Sprintf("### [%s] %s\n\n", f.Severity, f.Title))
			b.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Description))
			b.WriteString(fmt.Sprintf("- **Evidence Basis:** %s\n", f.EvidenceBasis))
			b.WriteString(fmt.Sprintf("- **Confidence:** `%s`\n", f.Confidence))
			b.WriteString(fmt.Sprintf("- **Limitations:** %s\n\n", f.Limitations))
		}
	}

	return b.String()
}

func sanitizeForMermaid(s string) string {
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, ".", "_")
	if len(s) > 20 {
		s = s[:20]
	}
	return s
}
