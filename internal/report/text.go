package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/klaudtrace/klaudtrace/internal/model"
)

// RenderText generates a structured, human-readable terminal report.
func RenderText(summary *model.IncidentSummary) string {
	var b strings.Builder

	b.WriteString("==================================================\n")
	b.WriteString("             KLAUDTRACE INCIDENT ANALYSIS         \n")
	b.WriteString("==================================================\n\n")

	// Time Window
	b.WriteString("Time Window:\n")
	if !summary.TimeWindowStart.IsZero() {
		dur := summary.TimeWindowEnd.Sub(summary.TimeWindowStart).Round(time.Second)
		b.WriteString(fmt.Sprintf("  %s to %s (%s)\n",
			summary.TimeWindowStart.UTC().Format("2006-01-02 15:04:05 UTC"),
			summary.TimeWindowEnd.UTC().Format("2006-01-02 15:04:05 UTC"),
			dur))
	} else {
		b.WriteString("  No events in time window\n")
	}
	b.WriteString(fmt.Sprintf("  Events: %d ingested | %d errors/denials\n\n", summary.TotalEvents, summary.ErrorEvents))

	// Identities
	b.WriteString("Identities:\n")
	if len(summary.Identities) == 0 {
		b.WriteString("  (None identified)\n")
	} else {
		for _, id := range summary.Identities {
			b.WriteString(fmt.Sprintf("  - %s (%s)\n", id.DisplayName(), id.Type))
		}
	}
	b.WriteString("\n")

	// Affected Classified Assets
	b.WriteString("Affected Assets:\n")
	if len(summary.AffectedAssets) == 0 {
		b.WriteString("  (No classified fintech assets affected)\n")
	} else {
		for _, a := range summary.AffectedAssets {
			b.WriteString(fmt.Sprintf("  - %s\n", a.DisplayString()))
		}
	}
	b.WriteString("\n")

	// Observed Paths
	b.WriteString("Observed Attack / Activity Paths:\n")
	if len(summary.Paths) == 0 {
		b.WriteString("  (No complex activity paths reconstructed)\n")
	} else {
		for _, p := range summary.Paths {
			b.WriteString(fmt.Sprintf("  [%s] %s (Confidence: %s)\n", p.ID, p.Title, p.Confidence))
			for i, node := range p.Nodes {
				prefix := "    "
				if i > 0 {
					prefix = "      ↓ "
				}
				if node.Detail != "" {
					b.WriteString(fmt.Sprintf("%s%s (%s)\n", prefix, node.Label, node.Detail))
				} else {
					b.WriteString(fmt.Sprintf("%s%s\n", prefix, node.Label))
				}
			}
			b.WriteString("\n")
		}
	}

	// Impact Findings
	b.WriteString("Impact Findings:\n")
	if len(summary.Findings) == 0 {
		b.WriteString("  (No impact findings triggered)\n")
	} else {
		for _, f := range summary.Findings {
			b.WriteString(fmt.Sprintf("  - [%s] %s [%s]\n", f.Severity, f.Title, f.Confidence))
			b.WriteString(fmt.Sprintf("    Details:     %s\n", f.Description))
			b.WriteString(fmt.Sprintf("    Evidence:    %s\n", f.EvidenceBasis))
			b.WriteString(fmt.Sprintf("    Limitations: %s\n", f.Limitations))
			b.WriteString(fmt.Sprintf("    Source Refs: %d event(s)\n", len(f.Evidence)))
			b.WriteString("\n")
		}
	}

	// Assessment Statement
	b.WriteString("Assessment:\n")
	b.WriteString(fmt.Sprintf("  %q\n\n", summary.AssessmentStatement))

	b.WriteString("==================================================\n")
	return b.String()
}

// RenderTimelineText renders a chronological timeline view for the CLI.
func RenderTimelineText(events []*model.NormalizedEvent) string {
	var b strings.Builder
	b.WriteString("CHRONOLOGICAL TIMELINE\n\n")

	for i, e := range events {
		timeStr := e.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC")
		status := "SUCCESS"
		if e.IsError() {
			status = fmt.Sprintf("FAILED (%s)", e.ErrorCode)
		}

		b.WriteString(fmt.Sprintf("[%3d] %s | %s | %s | %s\n",
			i+1, timeStr, e.Action.Normalized, e.Identity.DisplayName(), status))

		if len(e.Resources) > 0 {
			for _, r := range e.Resources {
				b.WriteString(fmt.Sprintf("      Resource: %s\n", r.DisplayString()))
			}
		}
		b.WriteString(fmt.Sprintf("      Event ID: %s | Source IP: %s\n", e.ID, e.SourceIPAddress))
	}

	return b.String()
}

// RenderPathsText renders only the reconstructed paths.
func RenderPathsText(paths []model.ObservedPath) string {
	var b strings.Builder
	b.WriteString("RECONSTRUCTED OBSERVED PATHS\n\n")

	for _, p := range paths {
		b.WriteString(fmt.Sprintf("=== %s (Confidence: %s) ===\n", p.Title, p.Confidence))
		for i, node := range p.Nodes {
			prefix := ""
			if i > 0 {
				prefix = "  ↓ "
			}
			if node.Detail != "" {
				b.WriteString(fmt.Sprintf("%s%s (%s)\n", prefix, node.Label, node.Detail))
			} else {
				b.WriteString(fmt.Sprintf("%s%s\n", prefix, node.Label))
			}
		}
		b.WriteString(fmt.Sprintf("Evidence events: %d\n\n", len(p.Evidence)))
	}

	return b.String()
}
