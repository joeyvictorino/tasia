package procns

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestAnalyze_HostPID(t *testing.T) {
	c := makeCollected(compose.Service{Name: "app", PidMode: "host"})
	r := Analyze(c)

	if r.Summary.TotalServices != 1 {
		t.Fatalf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.HostPidNamespace != 1 {
		t.Fatalf("expected 1 host pid, got %d", r.Summary.HostPidNamespace)
	}
	if len(r.Services[0].Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Services[0].Findings))
	}
	f := r.Services[0].Findings[0]
	if f.RuleID != "procns_host_pid" {
		t.Errorf("expected rule procns_host_pid, got %s", f.RuleID)
	}
	if f.Severity != "critical" {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
}

func TestAnalyze_SharedPID(t *testing.T) {
	c := makeCollected(compose.Service{Name: "sidecar", PidMode: "service:app"})
	r := Analyze(c)

	if r.Summary.SharedPidNamespace != 1 {
		t.Fatalf("expected 1 shared pid, got %d", r.Summary.SharedPidNamespace)
	}
	f := r.Services[0].Findings[0]
	if f.RuleID != "procns_shared_pid" {
		t.Errorf("expected rule procns_shared_pid, got %s", f.RuleID)
	}
	if f.Severity != "high" {
		t.Errorf("expected high severity, got %s", f.Severity)
	}
}

func TestAnalyze_ProcMount(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "monitor",
		Volumes: []string{"/proc:/host-proc"},
	})
	r := Analyze(c)

	if r.Summary.ProcMounted != 1 {
		t.Fatalf("expected 1 proc mount, got %d", r.Summary.ProcMounted)
	}
	f := r.Services[0].Findings[0]
	if f.RuleID != "procns_proc_mount" {
		t.Errorf("expected rule procns_proc_mount, got %s", f.RuleID)
	}
}

func TestAnalyze_SysMount(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "debug",
		Volumes: []string{"/sys:/host-sys"},
	})
	r := Analyze(c)

	if r.Summary.SysMounted != 1 {
		t.Fatalf("expected 1 sys mount, got %d", r.Summary.SysMounted)
	}
	f := r.Services[0].Findings[0]
	if f.RuleID != "procns_sys_mount" {
		t.Errorf("expected rule procns_sys_mount, got %s", f.RuleID)
	}
}

func TestAnalyze_ProcSubpath(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/proc/sys:/proc-sys:ro"},
	})
	r := Analyze(c)

	if r.Summary.ProcMounted != 1 {
		t.Fatalf("expected 1 proc mount for subpath, got %d", r.Summary.ProcMounted)
	}
}

func TestAnalyze_SysSubpath(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/sys/fs/cgroup:/cgroup"},
	})
	r := Analyze(c)

	if r.Summary.SysMounted != 1 {
		t.Fatalf("expected 1 sys mount for subpath, got %d", r.Summary.SysMounted)
	}
}

func TestAnalyze_SystempathsUnconfined(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "risky",
		SecurityOpt: []string{"systempaths=unconfined"},
	})
	r := Analyze(c)

	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	f := r.Services[0].Findings[0]
	if f.RuleID != "procns_systempaths_unconfined" {
		t.Errorf("expected procns_systempaths_unconfined, got %s", f.RuleID)
	}
}

func TestAnalyze_Clean(t *testing.T) {
	c := makeCollected(compose.Service{Name: "safe"})
	r := Analyze(c)

	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for clean service, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyze_MultipleFindings(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:        "dangerous",
		PidMode:     "host",
		Volumes:     []string{"/proc:/proc", "/sys:/sys"},
		SecurityOpt: []string{"systempaths=unconfined"},
	})
	r := Analyze(c)

	if r.Summary.TotalFindings != 4 {
		t.Fatalf("expected 4 findings, got %d", r.Summary.TotalFindings)
	}
	if r.Summary.HostPidNamespace != 1 {
		t.Errorf("expected 1 host pid, got %d", r.Summary.HostPidNamespace)
	}
	if r.Summary.ProcMounted != 1 {
		t.Errorf("expected 1 proc mount, got %d", r.Summary.ProcMounted)
	}
	if r.Summary.SysMounted != 1 {
		t.Errorf("expected 1 sys mount, got %d", r.Summary.SysMounted)
	}
}

func TestAnalyze_MultipleServices(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "a", PidMode: "host"},
		compose.Service{Name: "b"},
		compose.Service{Name: "c", Volumes: []string{"/proc:/proc"}},
	)
	r := Analyze(c)

	if r.Summary.TotalServices != 3 {
		t.Fatalf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings != 2 {
		t.Fatalf("expected 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	r := Report{
		Services: []ServiceResult{
			{
				Name:    "app",
				File:    "docker-compose.yml",
				PidMode: "host",
				Findings: []Finding{
					{
						Service:     "app",
						File:        "docker-compose.yml",
						RuleID:      "procns_host_pid",
						Severity:    "critical",
						Detail:      "Service uses host PID namespace",
						Remediation: "Remove pid: host",
					},
				},
			},
		},
		Summary: Summary{
			TotalServices:    1,
			HostPidNamespace: 1,
			TotalFindings:    1,
		},
	}

	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text output")
	}
	if !contains(text, "host PID namespace") {
		t.Error("expected text to mention host PID namespace count")
	}
	if !contains(text, "procns_host_pid") {
		t.Error("expected text to contain rule ID")
	}
}

func TestExtractHostPath(t *testing.T) {
	tests := []struct {
		vol  string
		want string
	}{
		{"/proc:/proc", "/proc"},
		{"/sys:/sys:ro", "/sys"},
		{"volume_name:/data", "volume_name"},
		{"/single", "/single"},
	}
	for _, tt := range tests {
		got := extractHostPath(tt.vol)
		if got != tt.want {
			t.Errorf("extractHostPath(%q) = %q, want %q", tt.vol, got, tt.want)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
