// Package report turns [rules.Finding] slices into output: terminal
// summaries, JSON (with schema_version), SARIF v2.1.0 for GitHub Code
// Scanning, and the .tasia/ hardening pack. The [Decide] function
// computes the PASS/BLOCKED/ERROR verdict from findings and the fail-on
// threshold.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/rules"
)

// Decide computes the overall decision and risk from the findings. A finding at
// or above the fail-on threshold blocks; --strict blocks on MEDIUM and above.
func Decide(findings []rules.Finding, failOn string, strict bool) (decision, risk string) {
	threshold := rules.Severity(strings.ToUpper(failOn))
	if threshold == "" {
		threshold = rules.SeverityHigh
	}

	maxSeverity := rules.SeverityLow
	blocked := false
	for _, f := range findings {
		if f.Severity.Rank() > maxSeverity.Rank() {
			maxSeverity = f.Severity
		}
		if f.Severity.Rank() >= threshold.Rank() {
			blocked = true
		}
		if strict && f.Severity.Rank() >= rules.SeverityMedium.Rank() {
			blocked = true
		}
	}

	decision = "PASS"
	if blocked {
		decision = "BLOCKED"
	}
	return decision, string(maxSeverity)
}

// severityOrder is the display order for grouped output, most severe first.
var severityOrder = []rules.Severity{
	rules.SeverityCritical, rules.SeverityHigh, rules.SeverityMedium, rules.SeverityLow,
}

// PrintSummary prints the terminal view used by review and ci.
func PrintSummary(findings []rules.Finding, decision, risk string) {
	fmt.Println("TASIA")
	fmt.Printf("Decision: %s\n", decision)
	fmt.Printf("Risk: %s\n", risk)

	// group by severity for nice output
	bySev := groupBySev(findings)
	for _, sev := range severityOrder {
		list := bySev[sev]
		if len(list) == 0 {
			continue
		}
		for _, f := range list {
			loc := ""
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			} else {
				loc = f.File
			}
			fmt.Printf("[%s] %s %s\n", f.Severity, loc, f.Title)
		}
	}

	if decision == "BLOCKED" {
		fmt.Printf("\n%d finding(s) require attention before shipping this private AI stack.\n", len(findings))
	} else {
		fmt.Println("\nNo blocking findings.")
	}
}

// PrintVerboseSummary prints the terminal view with full why/fix/evidence
// details under each finding, for debugging and remediation planning.
func PrintVerboseSummary(findings []rules.Finding, decision, risk string) {
	fmt.Println("TASIA")
	fmt.Printf("Decision: %s\n", decision)
	fmt.Printf("Risk: %s\n", risk)

	bySev := groupBySev(findings)
	for _, sev := range severityOrder {
		list := bySev[sev]
		if len(list) == 0 {
			continue
		}
		fmt.Printf("\n── %s ──\n", strings.ToUpper(string(sev)))
		for _, f := range list {
			loc := ""
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			} else {
				loc = f.File
			}
			fmt.Printf("\n  [%s] %s %s\n", f.Severity, loc, f.Title)
			if f.Evidence != "" {
				fmt.Printf("    Evidence: %s\n", f.Evidence)
			}
			if f.Why != "" {
				fmt.Printf("    Why:      %s\n", f.Why)
			}
			if f.Fix != "" {
				fmt.Printf("    Fix:      %s\n", f.Fix)
			}
		}
	}

	if decision == "BLOCKED" {
		fmt.Printf("\n%d finding(s) require attention before shipping this private AI stack.\n", len(findings))
	} else {
		fmt.Println("\nNo blocking findings.")
	}
}

// PrintErrorVerdict renders the fail-closed verdict when a config file could
// not be parsed. The gate reports ERROR rather than vouching for a stack it
// could not fully read.
func PrintErrorVerdict(errs []collect.ConfigError) {
	fmt.Println("TASIA")
	fmt.Println("Decision: ERROR")
	fmt.Println("Risk: UNKNOWN")
	fmt.Printf("\nCould not parse %d config file(s); refusing to vouch for this stack:\n", len(errs))
	for _, e := range errs {
		fmt.Printf("  - %s: %s\n", e.Path, e.Err)
	}
	fmt.Println("\nFix the file(s) above and re-run.")
}

// ErrorJSON is the machine-readable ERROR verdict for --format json.
func ErrorJSON(errs []collect.ConfigError) string {
	type parseError struct {
		Path  string `json:"path"`
		Error string `json:"error"`
	}
	out := struct {
		SchemaVersion string          `json:"schema_version"`
		Decision      string          `json:"decision"`
		Risk          string          `json:"risk"`
		ParseErrors   []parseError    `json:"parse_errors"`
		Findings      []rules.Finding `json:"findings"`
	}{SchemaVersion: SchemaVersion, Decision: "ERROR", Risk: "UNKNOWN", Findings: []rules.Finding{}}
	for _, e := range errs {
		out.ParseErrors = append(out.ParseErrors, parseError{Path: e.Path, Error: e.Err})
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b)
}

// ScanSummary holds aggregate statistics about a scan run. It is included in
// the JSON output for dashboards and trend tracking.
type ScanSummary struct {
	TotalFindings  int            `json:"total_findings"`
	BySeverity     map[string]int `json:"by_severity"`
	ByCategory     map[string]int `json:"by_category"`
	FilesScanned   int            `json:"files_scanned"`
	DurationMs     int64          `json:"duration_ms"`
}

// BuildSummary computes aggregate statistics from findings and scan metadata.
func BuildSummary(findings []rules.Finding, filesScanned int, durationMs int64) ScanSummary {
	bySev := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}
	byCat := map[string]int{}

	catalog := rules.CatalogMap()
	for _, f := range findings {
		bySev[string(f.Severity)]++
		cat := "other"
		if info, ok := catalog[f.ID]; ok {
			cat = info.Category
		}
		byCat[cat]++
	}

	return ScanSummary{
		TotalFindings: len(findings),
		BySeverity:    bySev,
		ByCategory:    byCat,
		FilesScanned:  filesScanned,
		DurationMs:    durationMs,
	}
}

type enrichedFinding struct {
	ID          string         `json:"id"`
	Severity    rules.Severity `json:"severity"`
	Title       string         `json:"title"`
	File        string         `json:"file"`
	Line        int            `json:"line"`
	Evidence    string         `json:"evidence"`
	Why         string         `json:"why"`
	Fix         string         `json:"fix"`
	Remediation *remediation   `json:"remediation,omitempty"`
}

type remediation struct {
	Summary  string   `json:"summary"`
	Category string   `json:"category"`
	DocURL   string   `json:"doc_url"`
	Refs     []string `json:"refs,omitempty"`
}

var remediationRefs = map[string][]string{
	"compose":    {"CIS Docker Benchmark 5.x", "OWASP Docker Top 10"},
	"agent":      {"OWASP LLM Top 10 LLM04", "CIS Docker Benchmark 5.x"},
	"dockerfile": {"CIS Docker Benchmark 4.1", "Dockerfile best practices"},
	"proxy":      {"OWASP API Security Top 10 API2"},
	"kubernetes": {"CIS Kubernetes Benchmark 5.2", "NSA Kubernetes Hardening Guide"},
	"helm":       {"CIS Kubernetes Benchmark 5.2"},
	"terraform":  {"CIS AWS/GCP/Azure Foundations Benchmark"},
	"manifest":   {},
}

func enrichFindings(findings []rules.Finding) []enrichedFinding {
	catalog := rules.CatalogMap()
	out := make([]enrichedFinding, len(findings))
	for i, f := range findings {
		out[i] = enrichedFinding{
			ID: f.ID, Severity: f.Severity, Title: f.Title,
			File: f.File, Line: f.Line, Evidence: f.Evidence,
			Why: f.Why, Fix: f.Fix,
		}
		info, ok := catalog[f.ID]
		if !ok {
			continue
		}
		r := &remediation{
			Summary:  f.Fix,
			Category: info.Category,
			DocURL:   "https://github.com/joeyvictorino/tasia/blob/main/docs/rules.md#" + f.ID,
		}
		if refs, ok := remediationRefs[info.Category]; ok && len(refs) > 0 {
			r.Refs = refs
		}
		out[i].Remediation = r
	}
	return out
}

// FindingsToJSON for --format json
func FindingsToJSON(findings []rules.Finding, decision, risk string, summary *ScanSummary) (string, error) {
	type out struct {
		SchemaVersion string             `json:"schema_version"`
		Decision      string             `json:"decision"`
		Risk          string             `json:"risk"`
		Summary       *ScanSummary       `json:"summary,omitempty"`
		Findings      []enrichedFinding  `json:"findings"`
	}
	o := out{SchemaVersion: SchemaVersion, Decision: decision, Risk: risk, Summary: summary, Findings: enrichFindings(findings)}
	b, err := json.MarshalIndent(o, "", "  ")
	return string(b), err
}

// FindingsToSARIF produces a SARIF v2.1.0 JSON log suitable for upload to
// GitHub Code Scanning (via github/codeql-action/upload-sarif).
func FindingsToSARIF(findings []rules.Finding, version string) (string, error) {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifArtifactLocation struct {
		URI string `json:"uri"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type sarifPhysicalLocation struct {
		ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
		Region           *sarifRegion          `json:"region,omitempty"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}
	type sarifHelp struct {
		Text string `json:"text"`
	}
	type sarifShortDesc struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string         `json:"id"`
		ShortDescription sarifShortDesc `json:"shortDescription"`
		HelpURI          string         `json:"helpUri"`
		Help             sarifHelp      `json:"help"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	ruleSet := map[string]bool{}
	var ruleList []sarifRule
	var results []sarifResult

	for _, f := range findings {
		if !ruleSet[f.ID] {
			ruleSet[f.ID] = true
			ruleList = append(ruleList, sarifRule{
				ID:               f.ID,
				ShortDescription: sarifShortDesc{Text: f.Title},
				HelpURI:          "https://github.com/joeyvictorino/tasia/blob/main/docs/rules.md#" + f.ID,
				Help:             sarifHelp{Text: f.Why + "\n\nFix: " + f.Fix},
			})
		}

		loc := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: f.File},
			},
		}
		if f.Line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
		}

		results = append(results, sarifResult{
			RuleID:    f.ID,
			Level:     severityToSARIF(f.Severity),
			Message:   sarifMessage{Text: f.Evidence},
			Locations: []sarifLocation{loc},
		})
	}

	if version == "" {
		version = "dev"
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "tasia",
					Version:        version,
					InformationURI: "https://github.com/joeyvictorino/tasia",
					Rules:          ruleList,
				},
			},
			Results: results,
		}},
	}

	b, err := json.MarshalIndent(log, "", "  ")
	return string(b), err
}

func severityToSARIF(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return "error"
	case rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	case rules.SeverityLow:
		return "note"
	default:
		return "note"
	}
}

// WriteArtifacts creates the full .tasia/ pack.
func WriteArtifacts(outDir string, c *collect.Collected, findings []rules.Finding, decision, risk string) error {
	// HARDENING_PLAN.md
	plan := buildHardeningPlan(findings, decision, risk, c)
	if err := os.WriteFile(filepath.Join(outDir, "HARDENING_PLAN.md"), []byte(plan), 0644); err != nil {
		return err
	}

	// EXECUTIVE_MEMO.md
	memo := buildExecutiveMemo(findings, decision, risk, c)
	if err := os.WriteFile(filepath.Join(outDir, "EXECUTIVE_MEMO.md"), []byte(memo), 0644); err != nil {
		return err
	}

	// ai-stack-manifest.json
	manifest := buildManifest(c, findings, decision, risk)
	mb, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "ai-stack-manifest.json"), mb, 0644); err != nil {
		return err
	}

	// docker-compose.hardened.override.yml
	override := buildHardenedOverride(c, findings)
	if err := os.WriteFile(filepath.Join(outDir, "docker-compose.hardened.override.yml"), []byte(override), 0644); err != nil {
		return err
	}

	// firewall-notes.md
	fw := buildFirewallNotes(c, findings)
	if err := os.WriteFile(filepath.Join(outDir, "firewall-notes.md"), []byte(fw), 0644); err != nil {
		return err
	}

	// findings.json
	fj, _ := json.MarshalIndent(findings, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "findings.json"), fj, 0644); err != nil {
		return err
	}

	// findings.toon (compact agent format)
	toon := buildFindingsToon(findings)
	if err := os.WriteFile(filepath.Join(outDir, "findings.toon"), []byte(toon), 0644); err != nil {
		return err
	}

	// LLM_REVIEW.md is intentionally NOT written here. It is produced only by
	// `tasia explain` so the pack never implies an LLM was consulted.

	return nil
}

func buildHardeningPlan(findings []rules.Finding, decision, risk string, c *collect.Collected) string {
	var b strings.Builder
	b.WriteString("# Tasia Hardening Plan\n\n")
	b.WriteString(fmt.Sprintf("## Decision\n%s\n\n", decision))
	b.WriteString(fmt.Sprintf("## Risk\n%s\n\n", risk))
	b.WriteString("## Summary\n")
	if decision == "BLOCKED" {
		b.WriteString("This stack exposes inference, UI, and/or vector database services beyond the minimum safe boundary.\n\n")
	} else {
		b.WriteString("Stack passes basic hardening checks.\n\n")
	}

	b.WriteString("## Findings\n")
	if len(findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}

	// group
	bySev := groupBySev(findings)
	for _, sev := range severityOrder {
		list := bySev[sev]
		for _, f := range list {
			b.WriteString(fmt.Sprintf("### %s: %s\n", f.Severity, f.Title))
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			b.WriteString(fmt.Sprintf("File: %s\n", loc))
			b.WriteString(fmt.Sprintf("Evidence: %s\n\n", f.Evidence))
			b.WriteString("Why it matters:\n")
			b.WriteString(f.Why + "\n\n")
			b.WriteString("Recommended fix:\n")
			b.WriteString(f.Fix + "\n\n")
			// suggested change for ports
			if strings.Contains(f.ID, "exposed_") || strings.Contains(f.Title, "published") {
				b.WriteString("Suggested change:\n")
				// naive from evidence or common
				if strings.Contains(f.Evidence, "11434") {
					b.WriteString(`"11434:11434" → "127.0.0.1:11434:11434"`)
				} else if strings.Contains(f.Evidence, "3000") || strings.Contains(f.Evidence, "8080") {
					b.WriteString(`"3000:8080" → "127.0.0.1:3000:8080"`)
				} else if strings.Contains(f.Evidence, "6333") {
					b.WriteString(`"6333:6333" → remove port or use internal network only`)
				} else {
					b.WriteString("Bind published ports to 127.0.0.1: or remove host publication.")
				}
				b.WriteString("\n\n")
			}
		}
	}
	return b.String()
}

func buildExecutiveMemo(findings []rules.Finding, decision, risk string, c *collect.Collected) string {
	var b strings.Builder
	b.WriteString("# Private AI Deployment Memo\n\n")
	b.WriteString("## Summary\n")
	b.WriteString("This local/private AI deployment should not be treated as production-ready until inference, UI, and retrieval services are restricted and documented.\n\n")
	b.WriteString("## Business Risk\n")
	b.WriteString("If this stack processes sensitive internal data, exposed services may create unauthorized access paths to model interfaces or retrieval infrastructure.\n\n")
	b.WriteString("## Recommendation\n")
	if decision == "BLOCKED" {
		b.WriteString("Do not ship this deployment as-is. Apply the hardening plan, document the AI stack manifest, and re-run Tasia.\n")
	} else {
		b.WriteString("Proceed but consider documenting the stack and re-running periodically.\n")
	}
	b.WriteString("\nGenerated by Tasia.\n")
	return b.String()
}

func buildManifest(c *collect.Collected, findings []rules.Finding, decision, risk string) map[string]interface{} {
	// simple aggregation
	ports := append([]int{}, c.PublishedPorts...)
	sort.Ints(ports)
	secrets := append([]string{}, c.SecretKeyNames...)
	sort.Strings(secrets)
	return map[string]interface{}{
		"tool":                   "tasia",
		"runtimes":               c.DetectedRuntimes,
		"interfaces":             c.DetectedInterfaces,
		"retrieval_databases":    c.DetectedRetrieval,
		"agent_runtimes":         c.DetectedAgentRuntimes,
		"published_ports":        ports,
		"secret_key_names_found": secrets,
		"risk":                   risk,
		"decision":               decision,
		"compose_files":          len(c.ComposeFiles),
	}
}

func buildHardenedOverride(c *collect.Collected, findings []rules.Finding) string {
	var b strings.Builder
	b.WriteString("# Suggested hardening generated by tasia. A starting point to review, not a drop-in file.\n")
	b.WriteString("# Compose APPENDS `ports` lists when it merges files, so passing this as a second -f file\n")
	b.WriteString("# does not remove the ports published in your base file. Apply the changes to the base\n")
	b.WriteString("# file, or mark the lists with the `!override` tag, then check the result with\n")
	b.WriteString("# `docker compose config`.\n")
	b.WriteString("# `internal: true` networks have no outbound access; a service that must pull models or\n")
	b.WriteString("# reach the internet needs an additional network.\n")
	b.WriteString("services:\n")
	// For every compose service we saw, suggest hardened version
	seen := map[string]bool{}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			key := svc.Name
			if seen[key] {
				continue
			}
			seen[key] = true

			imgLower := strings.ToLower(svc.Image)
			isVector := strings.Contains(imgLower, "qdrant") || strings.Contains(imgLower, "chroma") || strings.Contains(imgLower, "weaviate") || strings.Contains(imgLower, "milvus")
			b.WriteString(fmt.Sprintf("  %s:\n", svc.Name))
			// ports suggestion
			if isVector {
				// Vector DBs must not publish ports to host; access only via internal network
				b.WriteString("    ports: []\n")
			} else {
				hasPub := false
				for _, p := range svc.Ports {
					if p.HostPort > 0 {
						hasPub = true
						safe := fmt.Sprintf("\"127.0.0.1:%d:%d\"", p.HostPort, p.TargetPort)
						b.WriteString("    ports:\n")
						b.WriteString(fmt.Sprintf("      - %s\n", safe))
						break
					}
				}
				if !hasPub {
					b.WriteString("    ports: []\n")
				}
			}
			b.WriteString("    networks:\n      - ai_internal\n")
			if isVector {
				b.WriteString("    # vector DBs should not publish ports; access via internal network only\n")
			}
		}
	}
	b.WriteString("networks:\n  ai_internal:\n    internal: true\n")
	return b.String()
}

func buildFirewallNotes(c *collect.Collected, findings []rules.Finding) string {
	var b strings.Builder
	b.WriteString("# Firewall / Network Notes\n\n")
	b.WriteString("Suggested host firewall / docker network posture for private AI:\n\n")
	b.WriteString("- Do not expose 11434 (Ollama), 3000/8080 (WebUI), 6333 (Qdrant) etc. to the wider LAN.\n")
	b.WriteString("- Prefer Docker internal networks (as in the override).\n")
	b.WriteString("- If remote access to inference is required, front it with authenticated proxy + mTLS or Tailscale/Headscale.\n")
	b.WriteString("- Consider host firewall rules to allow only localhost for these ports.\n\n")
	b.WriteString("Tasia did not modify your host firewall.\n")
	return b.String()
}

func buildFindingsToon(findings []rules.Finding) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("findings[%d]:\n", len(findings)))
	for _, f := range findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		b.WriteString(fmt.Sprintf("  - id: %s\n", f.ID))
		b.WriteString(fmt.Sprintf("    sev: %s\n", f.Severity))
		b.WriteString(fmt.Sprintf("    file: %s\n", loc))
		b.WriteString(fmt.Sprintf("    why: %s\n", strings.ReplaceAll(f.Why, "\n", " ")))
		b.WriteString(fmt.Sprintf("    fix: %s\n", strings.ReplaceAll(f.Fix, "\n", " ")))
	}
	return b.String()
}

// ExitSummaryLine returns a one-line human-readable summary of findings by
// severity and the exit-code reason, suitable for printing to stderr.
func ExitSummaryLine(findings []rules.Finding, exitCode int) string {
	counts := map[rules.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	var parts []string
	for _, sev := range severityOrder {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(string(sev))))
		}
	}

	total := len(findings)
	breakdown := ""
	if len(parts) > 0 {
		breakdown = " (" + strings.Join(parts, ", ") + ")"
	}

	var reason string
	switch exitCode {
	case 0:
		reason = "pass"
	case 1:
		reason = "findings above threshold"
	case 2:
		reason = "error"
	default:
		reason = "unknown"
	}

	return fmt.Sprintf("Found %d issue(s)%s. Exit code: %d (%s)", total, breakdown, exitCode, reason)
}

func groupBySev(fs []rules.Finding) map[rules.Severity][]rules.Finding {
	m := map[rules.Severity][]rules.Finding{}
	for _, f := range fs {
		m[f.Severity] = append(m[f.Severity], f)
	}
	return m
}
