package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestDecideAndPrint(t *testing.T) {
	fs := []rules.Finding{
		{ID: "exposed_inference", Severity: "HIGH", Title: "Inference API published to all interfaces", File: "docker-compose.yml", Line: 5},
	}
	d, r := Decide(fs, "high", false)
	if d != "BLOCKED" || r != "HIGH" {
		t.Errorf("bad decide: %s %s", d, r)
	}
	// print does not panic
	PrintSummary(fs, d, r)
}

func TestManifestAndNoSecrets(t *testing.T) {
	c := &collect.Collected{
		DetectedRuntimes:   []string{"ollama"},
		DetectedInterfaces: []string{"open-webui"},
		DetectedRetrieval:  []string{"qdrant"},
		PublishedPorts:     []int{11434, 3000, 6333},
		SecretKeyNames:     []string{"HF_TOKEN"},
	}
	fs := []rules.Finding{{Severity: "HIGH"}}
	m := buildManifest(c, fs, "BLOCKED", "HIGH")
	b, _ := json.Marshal(m)
	s := string(b)
	if !strings.Contains(s, `"runtimes":["ollama"]`) {
		t.Error("manifest missing runtimes")
	}
	if strings.Contains(s, "hf_") || strings.Contains(s, "secretvalue") {
		t.Error("manifest may contain secret value")
	}
}

func TestHardenedOverride(t *testing.T) {
	c := &collect.Collected{
		Root: t.TempDir(),
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "ollama", Image: "ollama/ollama:latest", Ports: []compose.PortMapping{{HostPort: 11434, TargetPort: 11434, Raw: "11434:11434", Line: 5}}},
					{Name: "qdrant", Image: "qdrant/qdrant:latest", Ports: []compose.PortMapping{{HostPort: 6333, TargetPort: 6333, Raw: "6333:6333", Line: 12}}},
				},
			},
		},
	}
	fs := []rules.Finding{}
	override := buildHardenedOverride(c, fs)
	if !strings.Contains(override, "ai_internal") || !strings.Contains(override, "127.0.0.1:11434:11434") {
		t.Errorf("override did not generate expected localhost + internal net content; got:\n%s", override)
	}
	if !strings.Contains(override, "qdrant:\n    ports: []\n") && !strings.Contains(override, "ports: []\n    networks:\n      - ai_internal") {
		// accept either ordering as long as qdrant forces no published ports
		if !strings.Contains(override, "qdrant:") || strings.Contains(override, "127.0.0.1:6333") {
			t.Errorf("vector DB qdrant should force ports: [] not publish; got:\n%s", override)
		}
	}
	// The file must not pose as a drop-in: Compose appends ports lists on merge.
	if !strings.Contains(override, "APPENDS") || !strings.Contains(override, "!override") {
		t.Errorf("override should warn that Compose appends ports lists; got:\n%s", override)
	}
}

// Golden-style tests that drive the actual shipped report generators and WriteArtifacts.
func TestGoldenHardeningPlanAndMemo(t *testing.T) {
	c := &collect.Collected{
		Root:               ".",
		DetectedRuntimes:   []string{"ollama"},
		DetectedInterfaces: []string{"open-webui"},
		DetectedRetrieval:  []string{"qdrant"},
		PublishedPorts:     []int{11434, 3000, 6333},
	}
	fs := []rules.Finding{
		{ID: "exposed_inference", Severity: "HIGH", Title: "Inference API published to all interfaces", File: "docker-compose.yml", Line: 5, Evidence: "port=11434:11434", Why: "The inference API may be reachable...", Fix: "Bind to 127..."},
		{ID: "exposed_vector", Severity: "HIGH", Title: "Vector DB published to host", File: "docker-compose.yml", Line: 12, Evidence: "port=6333:6333", Why: "Vector DB...", Fix: "Use internal net"},
	}
	decision, risk := "BLOCKED", "HIGH"

	plan := buildHardeningPlan(fs, decision, risk, c)
	if !strings.Contains(plan, "# Tasia Hardening Plan") ||
		!strings.Contains(plan, "## Decision\nBLOCKED") ||
		!strings.Contains(plan, "File: docker-compose.yml:5") ||
		!strings.Contains(plan, "Why it matters:") ||
		!strings.Contains(plan, "Recommended fix:") ||
		!strings.Contains(plan, "Suggested change:") {
		t.Errorf("HARDENING_PLAN.md content missing required sections")
	}

	memo := buildExecutiveMemo(fs, decision, risk, c)
	if !strings.Contains(memo, "# Private AI Deployment Memo") ||
		!strings.Contains(memo, "Do not ship this deployment as-is") {
		t.Errorf("EXECUTIVE_MEMO missing expected language")
	}

	mani := buildManifest(c, fs, decision, risk)
	if mani["decision"] != "BLOCKED" || mani["risk"] != "HIGH" {
		t.Error("manifest decision/risk wrong")
	}
}

func TestWriteArtifactsGolden(t *testing.T) {
	scratch := t.TempDir()
	c := &collect.Collected{Root: ".", PublishedPorts: []int{11434}}
	fs := []rules.Finding{{ID: "exposed_inference", Severity: "HIGH", Title: "x", File: "c.yml", Line: 3, Why: "w", Fix: "f"}}
	decision, risk := "BLOCKED", "HIGH"

	outDir := filepath.Join(scratch, ".tasia")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := WriteArtifacts(outDir, c, fs, decision, risk); err != nil {
		t.Fatalf("WriteArtifacts: %v", err)
	}

	// Assert files + key content (drives the real writers)
	for _, name := range []string{"HARDENING_PLAN.md", "EXECUTIVE_MEMO.md", "ai-stack-manifest.json", "docker-compose.hardened.override.yml", "findings.json", "findings.toon", "firewall-notes.md"} {
		p := filepath.Join(outDir, name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing artifact %s", name)
			continue
		}
		b, _ := os.ReadFile(p)
		s := string(b)
		if name == "HARDENING_PLAN.md" && (!strings.Contains(s, "File: c.yml:3") || !strings.Contains(s, "Why it matters:")) {
			t.Errorf("%s missing expected sections", name)
		}
		if name == "ai-stack-manifest.json" && !strings.Contains(s, `"decision": "BLOCKED"`) {
			t.Errorf("%s missing decision", name)
		}
	}

	// review-time WriteArtifacts must NOT imply an LLM was consulted.
	if _, err := os.Stat(filepath.Join(outDir, "LLM_REVIEW.md")); err == nil {
		t.Error("WriteArtifacts should not write LLM_REVIEW.md; it is produced only by `tasia explain`")
	}
}

func TestFindingsToSARIF(t *testing.T) {
	fs := []rules.Finding{
		{ID: "exposed_inference", Severity: "HIGH", Title: "Inference API published to all interfaces", File: "docker-compose.yml", Line: 5, Evidence: "port=11434:11434", Why: "The inference API may be reachable", Fix: "Bind to 127.0.0.1"},
		{ID: "exposed_vector", Severity: "MEDIUM", Title: "Vector DB published to host", File: "docker-compose.yml", Line: 12, Evidence: "port=6333:6333", Why: "Vector DB", Fix: "Use internal net"},
		{ID: "exposed_inference", Severity: "HIGH", Title: "Inference API published to all interfaces", File: "compose2.yml", Line: 3, Evidence: "port=11434:11434", Why: "dup", Fix: "dup"},
	}
	out, err := FindingsToSARIF(fs, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}

	var sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &sarif); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v\n%s", err, out)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", sarif.Version)
	}
	if !strings.Contains(sarif.Schema, "sarif-schema-2.1.0") {
		t.Errorf("$schema missing sarif-schema-2.1.0: %q", sarif.Schema)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if run.Tool.Driver.Name != "tasia" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "0.1.0" {
		t.Errorf("driver version = %q", run.Tool.Driver.Version)
	}
	// Two distinct rule IDs (exposed_inference deduped)
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("rules = %d, want 2", len(run.Tool.Driver.Rules))
	}
	// Three results (one per finding)
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}
	// HIGH maps to error, MEDIUM maps to warning
	if run.Results[0].Level != "error" {
		t.Errorf("HIGH -> %q, want error", run.Results[0].Level)
	}
	if run.Results[1].Level != "warning" {
		t.Errorf("MEDIUM -> %q, want warning", run.Results[1].Level)
	}
	// Location includes line number
	if run.Results[0].Locations[0].PhysicalLocation.Region == nil || run.Results[0].Locations[0].PhysicalLocation.Region.StartLine != 5 {
		t.Errorf("first result location wrong: %+v", run.Results[0].Locations)
	}
}

func TestSARIFEmptyFindings(t *testing.T) {
	out, err := FindingsToSARIF(nil, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"results": null`) && !strings.Contains(out, `"results":null`) {
		// null is fine for empty results in SARIF
	}
	if !strings.Contains(out, `"version": "2.1.0"`) {
		t.Errorf("empty SARIF missing version")
	}
}

func TestSeverityToSARIFMapping(t *testing.T) {
	cases := []struct {
		sev  rules.Severity
		want string
	}{
		{rules.SeverityCritical, "error"},
		{rules.SeverityHigh, "error"},
		{rules.SeverityMedium, "warning"},
		{rules.SeverityLow, "note"},
	}
	for _, tc := range cases {
		fs := []rules.Finding{{ID: "test", Severity: tc.sev, Title: "t", File: "f.yml", Line: 1, Evidence: "e", Why: "w", Fix: "f"}}
		out, _ := FindingsToSARIF(fs, "dev")
		if !strings.Contains(out, `"level": "`+tc.want+`"`) {
			t.Errorf("%s: expected level %q in output", tc.sev, tc.want)
		}
	}
}

func TestAllCatalogRulesProduceValidSARIFLevel(t *testing.T) {
	validLevels := map[string]bool{"error": true, "warning": true, "note": true}
	catalog := rules.Catalog()
	if len(catalog) == 0 {
		t.Fatal("catalog is empty")
	}
	for _, r := range catalog {
		if r.Default == "" {
			t.Errorf("rule %s has empty default severity", r.ID)
			continue
		}
		f := rules.Finding{
			ID:       r.ID,
			Severity: r.Default,
			Title:    r.Title,
			File:     "test.yml",
			Line:     1,
			Evidence: "test",
			Why:      "test",
			Fix:      "test",
		}
		out, err := FindingsToSARIF([]rules.Finding{f}, "test")
		if err != nil {
			t.Errorf("rule %s: FindingsToSARIF error: %v", r.ID, err)
			continue
		}
		var sarif struct {
			Runs []struct {
				Results []struct {
					Level string `json:"level"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal([]byte(out), &sarif); err != nil {
			t.Errorf("rule %s: invalid SARIF JSON: %v", r.ID, err)
			continue
		}
		if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
			t.Errorf("rule %s: expected 1 run with 1 result", r.ID)
			continue
		}
		level := sarif.Runs[0].Results[0].Level
		if !validLevels[level] {
			t.Errorf("rule %s (severity %s): SARIF level %q is not valid (want error/warning/note)", r.ID, r.Default, level)
		}
	}
	t.Logf("verified %d catalog rules produce valid SARIF levels", len(catalog))
}

func TestBuildSummary(t *testing.T) {
	findings := []rules.Finding{
		{ID: "exposed_inference", Severity: rules.SeverityHigh, Title: "a", File: "f.yml"},
		{ID: "exposed_vector", Severity: rules.SeverityHigh, Title: "b", File: "f.yml"},
		{ID: "latest_image", Severity: rules.SeverityMedium, Title: "c", File: "f.yml"},
		{ID: "vector_db_no_auth", Severity: rules.SeverityLow, Title: "d", File: "f.yml"},
	}
	s := BuildSummary(findings, 5, 123)
	if s.TotalFindings != 4 {
		t.Errorf("TotalFindings = %d, want 4", s.TotalFindings)
	}
	if s.BySeverity["HIGH"] != 2 {
		t.Errorf("BySeverity[HIGH] = %d, want 2", s.BySeverity["HIGH"])
	}
	if s.BySeverity["MEDIUM"] != 1 {
		t.Errorf("BySeverity[MEDIUM] = %d, want 1", s.BySeverity["MEDIUM"])
	}
	if s.BySeverity["LOW"] != 1 {
		t.Errorf("BySeverity[LOW] = %d, want 1", s.BySeverity["LOW"])
	}
	if s.BySeverity["CRITICAL"] != 0 {
		t.Errorf("BySeverity[CRITICAL] = %d, want 0", s.BySeverity["CRITICAL"])
	}
	if s.ByCategory["compose"] != 4 {
		t.Errorf("ByCategory[compose] = %d, want 4", s.ByCategory["compose"])
	}
	if s.FilesScanned != 5 {
		t.Errorf("FilesScanned = %d, want 5", s.FilesScanned)
	}
	if s.DurationMs != 123 {
		t.Errorf("DurationMs = %d, want 123", s.DurationMs)
	}
}

func TestBuildSummaryEmpty(t *testing.T) {
	s := BuildSummary(nil, 0, 0)
	if s.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0", s.TotalFindings)
	}
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if s.BySeverity[sev] != 0 {
			t.Errorf("BySeverity[%s] = %d, want 0", sev, s.BySeverity[sev])
		}
	}
}

func TestFindingsToJSONIncludesSummary(t *testing.T) {
	findings := []rules.Finding{
		{ID: "exposed_inference", Severity: rules.SeverityHigh, Title: "a", File: "f.yml", Line: 1, Evidence: "e", Why: "w", Fix: "f"},
	}
	summary := BuildSummary(findings, 3, 42)
	out, err := FindingsToJSON(findings, "BLOCKED", "HIGH", &summary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"summary"`) {
		t.Error("JSON output should contain summary")
	}
	if !strings.Contains(out, `"total_findings": 1`) {
		t.Error("summary should contain total_findings")
	}
	if !strings.Contains(out, `"files_scanned": 3`) {
		t.Error("summary should contain files_scanned")
	}
	if !strings.Contains(out, `"duration_ms": 42`) {
		t.Error("summary should contain duration_ms")
	}
	if !strings.Contains(out, `"by_severity"`) {
		t.Error("summary should contain by_severity")
	}
	if !strings.Contains(out, `"by_category"`) {
		t.Error("summary should contain by_category")
	}
}

func TestFindingsToJSONOmitsSummaryWhenNil(t *testing.T) {
	out, err := FindingsToJSON(nil, "PASS", "LOW", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, `"summary"`) {
		t.Error("JSON output should omit summary when nil")
	}
}

func TestBuildSummary(t *testing.T) {
	findings := []rules.Finding{
		{ID: "exposed_inference", Severity: rules.SeverityHigh, Title: "t", File: "a.yml", Line: 1, Evidence: "e", Why: "w", Fix: "f"},
		{ID: "exposed_vector", Severity: rules.SeverityHigh, Title: "t", File: "a.yml", Line: 2, Evidence: "e", Why: "w", Fix: "f"},
		{ID: "privileged_container", Severity: rules.SeverityCritical, Title: "t", File: "a.yml", Line: 3, Evidence: "e", Why: "w", Fix: "f"},
		{ID: "latest_image", Severity: rules.SeverityMedium, Title: "t", File: "a.yml", Line: 4, Evidence: "e", Why: "w", Fix: "f"},
		{ID: "kube_privileged", Severity: rules.SeverityCritical, Title: "t", File: "k.yaml", Line: 1, Evidence: "e", Why: "w", Fix: "f"},
	}
	s := BuildSummary(findings, 7, 42)
	if s.TotalFindings != 5 {
		t.Errorf("total = %d, want 5", s.TotalFindings)
	}
	if s.BySeverity["CRITICAL"] != 2 {
		t.Errorf("CRITICAL = %d, want 2", s.BySeverity["CRITICAL"])
	}
	if s.BySeverity["HIGH"] != 2 {
		t.Errorf("HIGH = %d, want 2", s.BySeverity["HIGH"])
	}
	if s.BySeverity["MEDIUM"] != 1 {
		t.Errorf("MEDIUM = %d, want 1", s.BySeverity["MEDIUM"])
	}
	if s.BySeverity["LOW"] != 0 {
		t.Errorf("LOW = %d, want 0", s.BySeverity["LOW"])
	}
	if s.ByCategory["compose"] != 3 {
		t.Errorf("compose = %d, want 3", s.ByCategory["compose"])
	}
	if s.ByCategory["kubernetes"] != 1 {
		t.Errorf("kubernetes = %d, want 1", s.ByCategory["kubernetes"])
	}
	if s.FilesScanned != 7 {
		t.Errorf("files = %d, want 7", s.FilesScanned)
	}
	if s.DurationMs != 42 {
		t.Errorf("duration = %d, want 42", s.DurationMs)
	}
}

func TestFindingsToJSONIncludesSummary(t *testing.T) {
	findings := []rules.Finding{
		{ID: "exposed_inference", Severity: rules.SeverityHigh, Title: "t", File: "a.yml", Line: 1, Evidence: "e", Why: "w", Fix: "f"},
	}
	s := BuildSummary(findings, 3, 15)
	out, err := FindingsToJSON(findings, "BLOCKED", "HIGH", &s)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}
	summary, ok := parsed["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("JSON output should include summary object")
	}
	if int(summary["total_findings"].(float64)) != 1 {
		t.Errorf("summary.total_findings = %v, want 1", summary["total_findings"])
	}
	if int(summary["files_scanned"].(float64)) != 3 {
		t.Errorf("summary.files_scanned = %v, want 3", summary["files_scanned"])
	}
	if int(summary["duration_ms"].(float64)) != 15 {
		t.Errorf("summary.duration_ms = %v, want 15", summary["duration_ms"])
	}
	bySev, ok := summary["by_severity"].(map[string]interface{})
	if !ok {
		t.Fatal("summary should have by_severity")
	}
	if int(bySev["HIGH"].(float64)) != 1 {
		t.Errorf("by_severity.HIGH = %v, want 1", bySev["HIGH"])
	}
}

func TestFindingsToJSONOmitsSummaryWhenNil(t *testing.T) {
	out, err := FindingsToJSON(nil, "PASS", "LOW", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "summary") {
		t.Error("summary should be omitted when nil")
	}
}

func TestErrorJSONIsValidFailClosed(t *testing.T) {
	out := ErrorJSON([]collect.ConfigError{{Path: "docker-compose.yml", Err: "yaml: line 2: bad"}})
	var parsed struct {
		Decision    string `json:"decision"`
		ParseErrors []struct {
			Path  string `json:"path"`
			Error string `json:"error"`
		} `json:"parse_errors"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("ErrorJSON is not valid JSON: %v", err)
	}
	if parsed.Decision != "ERROR" {
		t.Errorf("decision = %q, want ERROR", parsed.Decision)
	}
	if len(parsed.ParseErrors) != 1 || parsed.ParseErrors[0].Path != "docker-compose.yml" {
		t.Errorf("parse_errors not carried through: %+v", parsed.ParseErrors)
	}
}
