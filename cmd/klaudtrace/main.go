package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/klaudtrace/klaudtrace/internal/analysis"
	"github.com/klaudtrace/klaudtrace/internal/classification"
	"github.com/klaudtrace/klaudtrace/internal/correlation"
	"github.com/klaudtrace/klaudtrace/internal/ingest"
	"github.com/klaudtrace/klaudtrace/internal/report"
)

const version = "0.1.0-mvp"

func printUsage() {
	fmt.Fprintf(os.Stderr, `KlaudTrace — AWS Incident Reconstruction for Fintech Environments (v%s)

Usage:
  klaudtrace <command> [options] <logfile>

Commands:
  analyze   Reconstruct incident, affected assets, observed paths, and actual impact
  timeline  Output deterministic chronological timeline of observed API calls
  paths     Visualize reconstructed activity and attack paths
  report    Generate structured report (text, json, or markdown)
  version   Display KlaudTrace version

Common Flags:
  --config <path>     Path to custom asset classification JSON file
  --format <format>   Output format: text (default), json, markdown
  --output <path>     Write output to file instead of stdout

Examples:
  klaudtrace analyze fixtures/cloudtrail/scenario1.json
  klaudtrace timeline fixtures/cloudtrail/scenario1.json
  klaudtrace paths fixtures/cloudtrail/scenario1.json
  klaudtrace report fixtures/cloudtrail/scenario1.json --format=markdown --output=report.md
`, version)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "version", "--version", "-v":
		fmt.Printf("KlaudTrace v%s (AWS Post-Attack Reconstruction Engine)\n", version)
		return

	case "help", "--help", "-h":
		printUsage()
		return

	case "analyze", "timeline", "paths", "report":
		runCommand(cmd, os.Args[2:])

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %q\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func runCommand(command string, rawArgs []string) {
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	var (
		configPath string
		format     string
		outputPath string
	)

	fs.StringVar(&configPath, "config", "", "Path to custom asset classification rules JSON")
	fs.StringVar(&format, "format", "text", "Output format: text, json, markdown")
	fs.StringVar(&outputPath, "output", "", "Write output to file")

	flags, pos := splitFlagsAndPositional(rawArgs)
	_ = fs.Parse(flags)

	if len(pos) < 1 {
		fmt.Fprintf(os.Stderr, "Error: Missing CloudTrail log file argument.\n\n")
		fs.Usage()
		os.Exit(1)
	}

	logFile := pos[0]

	// 1. Ingestion
	ingestRes, err := ingest.IngestFile(logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ingestion Error: %v\n", err)
		os.Exit(1)
	}

	if len(ingestRes.Warnings) > 0 {
		for _, w := range ingestRes.Warnings {
			fmt.Fprintf(os.Stderr, "[WARN] %s\n", w)
		}
	}

	if len(ingestRes.Events) == 0 {
		fmt.Fprintf(os.Stderr, "No valid events found in %q.\n", logFile)
		os.Exit(1)
	}

	// 2. Classification Configuration
	classifier := classification.New()
	if configPath != "" {
		if err := classifier.LoadConfigFile(configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading classification config %q: %v\n", configPath, err)
			os.Exit(1)
		}
	}

	// 3. Correlation Pipeline
	events, _ := correlation.CorrelatePipeline(ingestRes.Events, classifier)
	groups := correlation.GroupBySession(events)

	// 4. Command Execution
	var outputContent string

	switch command {
	case "timeline":
		outputContent = report.RenderTimelineText(events)

	case "paths":
		paths := analysis.ReconstructPaths(groups)
		outputContent = report.RenderPathsText(paths)

	case "analyze", "report":
		paths := analysis.ReconstructPaths(groups)
		findings := analysis.EvaluateImpact(events, paths, groups)
		summary := analysis.GenerateIncidentSummary(events, paths, findings)

		switch strings.ToLower(format) {
		case "json":
			jsonBytes, err := report.RenderJSON(summary)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed generating JSON report: %v\n", err)
				os.Exit(1)
			}
			outputContent = string(jsonBytes)
		case "markdown", "md":
			outputContent = report.RenderMarkdown(summary)
		default:
			outputContent = report.RenderText(summary)
		}
	}

	// 5. Output destination
	if outputPath != "" {
		if err := os.WriteFile(outputPath, []byte(outputContent), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write output to %q: %v\n", outputPath, err)
			os.Exit(1)
		}
		fmt.Printf("Report successfully written to %s\n", outputPath)
	} else {
		fmt.Print(outputContent)
	}
}

func splitFlagsAndPositional(args []string) ([]string, []string) {
	var flags []string
	var pos []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if strings.Contains(arg, "=") {
				continue
			}
			if arg == "--config" || arg == "-config" || arg == "--format" || arg == "-format" || arg == "--output" || arg == "-output" {
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					i++
					flags = append(flags, args[i])
				}
			}
		} else {
			pos = append(pos, arg)
		}
	}
	return flags, pos
}
