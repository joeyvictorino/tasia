package capabilities

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzePrivilegedCompose(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "agent", Image: "n8n", Privileged: true, PrivLine: 10},
				},
			},
		},
	}
	r := Analyze(col)
	if r.Summary.PrivilegedCount != 1 {
		t.Errorf("privileged count = %d, want 1", r.Summary.PrivilegedCount)
	}
	found := false
	for _, f := range r.Findings {
		if f.Category == "privileged" && f.Severity == SevCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected critical privileged finding")
	}
}

func TestAnalyzeDangerousCaps(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "compose.yaml",
				Services: []compose.Service{
					{
						Name:       "probe",
						Image:      "custom/probe",
						CapAdd:     []string{"SYS_ADMIN", "NET_RAW"},
						CapAddLine: 15,
						CapDrop:    []string{"ALL"},
					},
				},
			},
		},
	}
	r := Analyze(col)
	if r.Summary.DangerousCapCount != 1 {
		t.Errorf("dangerous cap count = %d, want 1", r.Summary.DangerousCapCount)
	}
	var capFinding *Finding
	for i, f := range r.Findings {
		if f.Category == "dangerous_capability" {
			capFinding = &r.Findings[i]
		}
	}
	if capFinding == nil {
		t.Fatal("expected dangerous_capability finding")
	}
	if capFinding.Severity != SevCritical {
		t.Errorf("severity = %s, want critical (SYS_ADMIN present)", capFinding.Severity)
	}
	if len(capFinding.Caps) != 2 {
		t.Errorf("caps = %v, want 2 entries", capFinding.Caps)
	}
}

func TestAnalyzeNoCapDropAll(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx"},
				},
			},
		},
	}
	r := Analyze(col)
	found := false
	for _, f := range r.Findings {
		if f.Category == "no_cap_drop_all" {
			found = true
		}
	}
	if !found {
		t.Error("expected no_cap_drop_all finding for service without cap_drop: [ALL]")
	}
}

func TestAnalyzeSeccompPresent(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "compose.yml",
				Services: []compose.Service{
					{
						Name:        "secure",
						Image:       "app",
						SecurityOpt: []string{"seccomp:custom.json"},
						CapDrop:     []string{"ALL"},
					},
				},
			},
		},
	}
	r := Analyze(col)
	if len(r.Profiles) != 1 {
		t.Fatalf("profiles = %d, want 1", len(r.Profiles))
	}
	if !r.Profiles[0].HasSeccomp {
		t.Error("expected HasSeccomp=true")
	}
	for _, f := range r.Findings {
		if f.Category == "no_seccomp" {
			t.Error("should not flag no_seccomp when seccomp is present")
		}
	}
}

func TestAnalyzeKubePrivileged(t *testing.T) {
	col := &collect.Collected{
		KubeManifests: []collect.KubeManifest{
			{
				Path: "deploy.yaml",
				Containers: []collect.KubeContainer{
					{
						Name:           "ollama",
						Image:          "ollama/ollama",
						Privileged:     true,
						PrivilegedLine: 28,
						RunAsRoot:      true,
						RunAsRootLine:  29,
					},
				},
			},
		},
	}
	r := Analyze(col)
	if r.Summary.PrivilegedCount != 1 {
		t.Errorf("privileged = %d, want 1", r.Summary.PrivilegedCount)
	}
	cats := map[string]bool{}
	for _, f := range r.Findings {
		cats[f.Category] = true
	}
	if !cats["privileged"] {
		t.Error("missing privileged finding for kube container")
	}
	if !cats["run_as_root"] {
		t.Error("missing run_as_root finding for kube container")
	}
}

func TestAnalyzeCleanStack(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "compose.yml",
				Services: []compose.Service{
					{
						Name:        "app",
						Image:       "myapp",
						CapDrop:     []string{"ALL"},
						CapAdd:      []string{"NET_BIND_SERVICE"},
						SecurityOpt: []string{"seccomp:default.json", "no-new-privileges:true"},
					},
				},
			},
		},
	}
	r := Analyze(col)
	for _, f := range r.Findings {
		if f.Severity == SevCritical || f.Severity == SevHigh {
			t.Errorf("clean stack should have no critical/high findings, got: %s - %s", f.Category, f.Description)
		}
	}
}

func TestFormatTextOutput(t *testing.T) {
	r := Report{
		Profiles: []ServiceProfile{
			{Service: "web", Image: "nginx", Privileged: false, HasSeccomp: true},
			{Service: "agent", Image: "n8n", Privileged: true, CapAdd: []string{"SYS_ADMIN"}},
		},
		Findings: []Finding{
			{Service: "agent", Severity: SevCritical, Category: "privileged", Description: "runs privileged"},
		},
		Summary: Summary{
			TotalServices:   2,
			PrivilegedCount: 1,
			BySeverity:      map[string]int{"critical": 1},
		},
	}
	text := FormatText(r)
	if !strings.Contains(text, "Container Capability Analysis") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "Privileged") {
		t.Error("missing privileged column")
	}
	if !strings.Contains(text, "[CRITICAL]") {
		t.Error("missing severity in findings")
	}
}

func TestSeverityOrdering(t *testing.T) {
	col := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "compose.yml",
				Services: []compose.Service{
					{Name: "a", Image: "img", Privileged: true, PrivLine: 1},
					{Name: "b", Image: "img2", CapAdd: []string{"NET_RAW"}, CapAddLine: 5},
				},
			},
		},
	}
	r := Analyze(col)
	if len(r.Findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(r.Findings))
	}
	if sevRank(r.Findings[0].Severity) > sevRank(r.Findings[1].Severity) {
		t.Error("findings should be sorted most-severe first")
	}
}

func TestHasDropAll(t *testing.T) {
	if !hasDropAll([]string{"all"}) {
		t.Error("should match case-insensitive ALL")
	}
	if hasDropAll([]string{"NET_RAW"}) {
		t.Error("NET_RAW is not ALL")
	}
}

func TestFilterDangerous(t *testing.T) {
	caps := filterDangerous([]string{"NET_BIND_SERVICE", "SYS_ADMIN", "chown"})
	if len(caps) != 1 || caps[0] != "SYS_ADMIN" {
		t.Errorf("filterDangerous = %v, want [SYS_ADMIN]", caps)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short = %q", got)
	}
	if got := truncate("a-very-long-string", 10); len(got) > 10 {
		t.Errorf("truncate long = %q, len %d > 10", got, len(got))
	}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Errorf("empty collected should have 0 services, got %d", r.Summary.TotalServices)
	}
	if len(r.Findings) != 0 {
		t.Errorf("empty collected should have 0 findings, got %d", len(r.Findings))
	}
}
