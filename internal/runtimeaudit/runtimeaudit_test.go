package runtimeaudit

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

func TestNoReadOnly(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent", Init: true})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "runtime_no_readonly" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected runtime_no_readonly finding")
	}
}

func TestReadOnlySet(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent", ReadOnly: true, Init: true})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "runtime_no_readonly" {
			t.Fatal("should not flag read_only when set")
		}
	}
}

func TestInteractiveMode(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent", StdinOpen: true, Tty: true, Init: true})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "runtime_interactive" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected runtime_interactive finding")
	}
}

func TestStdinOnlyNoFlag(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent", StdinOpen: true, Tty: false, Init: true})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "runtime_interactive" {
			t.Fatal("stdin_open alone should not trigger interactive finding")
		}
	}
}

func TestNoInit(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent", ReadOnly: true})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "runtime_no_init" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected runtime_no_init finding")
	}
}

func TestInitSet(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent", ReadOnly: true, Init: true})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "runtime_no_init" {
			t.Fatal("should not flag init when set")
		}
	}
}

func TestStopGraceLong(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent", ReadOnly: true, Init: true, StopGracePeriod: "60s"})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "runtime_stop_grace" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected runtime_stop_grace finding for 60s")
	}
}

func TestStopGraceMinutes(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent", ReadOnly: true, Init: true, StopGracePeriod: "2m"})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "runtime_stop_grace" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected runtime_stop_grace finding for 2m (120s)")
	}
}

func TestStopGraceOK(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent", ReadOnly: true, Init: true, StopGracePeriod: "10s"})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "runtime_stop_grace" {
			t.Fatal("10s should not trigger stop_grace finding")
		}
	}
}

func TestNvidiaNoHardening(t *testing.T) {
	c := makeCollected(compose.Service{Name: "gpu-agent", Runtime: "nvidia", Init: true})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "runtime_nvidia_no_hardening" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected runtime_nvidia_no_hardening finding")
	}
}

func TestNvidiaWithReadOnly(t *testing.T) {
	c := makeCollected(compose.Service{Name: "gpu-agent", Runtime: "nvidia", ReadOnly: true, Init: true})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "runtime_nvidia_no_hardening" {
			t.Fatal("nvidia with read_only should not trigger hardening finding")
		}
	}
}

func TestFullySecure(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent", ReadOnly: true, Init: true})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Fatalf("fully secure service should have 0 findings, got %d", len(r.Services[0].Findings))
	}
}

func TestMultipleServices(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "secure", ReadOnly: true, Init: true},
		compose.Service{Name: "insecure"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings < 2 {
		t.Fatalf("insecure service should have at least 2 findings, total %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("format text returned empty")
	}
	if !containsStr(text, "Container Runtime Audit") {
		t.Fatal("missing header")
	}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatal("expected 0 services for empty input")
	}
}

func TestParseGracePeriod(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"30s", 30},
		{"2m", 120},
		{"45", 45},
		{"", 0},
	}
	for _, tt := range tests {
		got := parseGracePeriod(tt.input)
		if got != tt.want {
			t.Errorf("parseGracePeriod(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
