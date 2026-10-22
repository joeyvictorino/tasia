package report

import (
	"encoding/json"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/rules"
)

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool              `json:"tool"`
	Results     []sarifResult          `json:"results"`
	Invocations []sarifInvocation      `json:"invocations,omitempty"`
	Properties  map[string]interface{} `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string                `json:"name"`
	InformationURI string                `json:"informationUri"`
	Rules          []sarifRuleDescriptor `json:"rules,omitempty"`
}

type sarifRuleDescriptor struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	ShortDescription     sarifMessage       `json:"shortDescription"`
	FullDescription      sarifMessage       `json:"fullDescription"`
	Help                 sarifMessage       `json:"help"`
	DefaultConfiguration sarifConfiguration `json:"defaultConfiguration"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

// FindingsToSARIF renders deterministic SARIF 2.1.0 suitable for GitHub code scanning.
func FindingsToSARIF(findings []rules.Finding, decision, risk string) (string, error) {
	descriptors := make([]sarifRuleDescriptor, 0)
	results := make([]sarifResult, 0, len(findings))
	seenRules := make(map[string]bool)

	for _, finding := range findings {
		level := sarifLevel(finding.Severity)
		if !seenRules[finding.ID] {
			seenRules[finding.ID] = true
			descriptors = append(descriptors, sarifRuleDescriptor{
				ID:               finding.ID,
				Name:             finding.ID,
				ShortDescription: sarifMessage{Text: finding.Title},
				FullDescription:  sarifMessage{Text: finding.Why},
				Help:             sarifMessage{Markdown: finding.Fix},
				DefaultConfiguration: sarifConfiguration{
					Level: level,
				},
			})
		}

		result := sarifResult{
			RuleID:  finding.ID,
			Level:   level,
			Message: sarifMessage{Text: finding.Title + ". " + finding.Fix},
		}
		if finding.File != "" {
			physical := sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: filepath.ToSlash(finding.File)},
			}
			if finding.Line > 0 {
				physical.Region = &sarifRegion{StartLine: finding.Line}
			}
			result.Locations = []sarifLocation{{PhysicalLocation: physical}}
		}
		results = append(results, result)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Tasia",
				InformationURI: "https://github.com/joeyvictorino/tasia",
				Rules:          descriptors,
			}},
			Results: results,
			Properties: map[string]interface{}{
				"decision": decision,
				"risk":     risk,
			},
		}},
	}
	b, err := json.MarshalIndent(log, "", "  ")
	return string(b), err
}

// ErrorSARIF preserves Tasia's fail-closed parse verdict in machine-readable output.
func ErrorSARIF(errs []collect.ConfigError) string {
	notifications := make([]sarifNotification, 0, len(errs))
	for _, configErr := range errs {
		notification := sarifNotification{
			Level:   "error",
			Message: sarifMessage{Text: configErr.Err},
		}
		if configErr.Path != "" {
			notification.Locations = []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: filepath.ToSlash(configErr.Path)},
			}}}
		}
		notifications = append(notifications, notification)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Tasia",
				InformationURI: "https://github.com/joeyvictorino/tasia",
			}},
			Results: []sarifResult{},
			Invocations: []sarifInvocation{{
				ExecutionSuccessful:        false,
				ToolExecutionNotifications: notifications,
			}},
			Properties: map[string]interface{}{
				"decision": "ERROR",
				"risk":     "UNKNOWN",
			},
		}},
	}
	b, _ := json.MarshalIndent(log, "", "  ")
	return string(b)
}

func sarifLevel(severity rules.Severity) string {
	switch severity {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
