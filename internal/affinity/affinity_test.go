package affinity

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func svc(name string) compose.Service {
	return compose.Service{Name: name}
}

func TestParseCPUs(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		{"", 0},
		{"1.5", 1.5},
		{"2", 2},
		{"0.5", 0.5},
		{"invalid", 0},
	}
	for _, tt := range tests {
		got := parseCPUs(tt.input)
		if got != tt.want {
			t.Errorf("parseCPUs(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseMemBytes(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"", 0},
		{"512m", 512 * 1024 * 1024},
		{"1g", 1024 * 1024 * 1024},
		{"256k", 256 * 1024},
		{"invalid", 0},
	}
	for _, tt := range tests {
		got := parseMemBytes(tt.input)
		if got != tt.want {
			t.Errorf("parseMemBytes(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestNoCPULimit(t *testing.T) {
	s := svc("worker")
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_cpu_limit" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected no_cpu_limit finding")
	}
}

func TestNoMemLimit(t *testing.T) {
	s := svc("worker")
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_mem_limit" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected no_mem_limit finding")
	}
}

func TestWithCPULimit(t *testing.T) {
	s := svc("worker")
	s.CPUs = "1.0"
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_cpu_limit" {
				t.Fatal("should not have no_cpu_limit when CPUs is set")
			}
		}
	}
}

func TestHighCPU(t *testing.T) {
	s := svc("compute")
	s.CPUs = "8.0"
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "high_cpu_allocation" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected high_cpu_allocation finding")
	}
}

func TestHighMem(t *testing.T) {
	s := svc("bigmem")
	s.MemLimit = "16g"
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "high_mem_allocation" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected high_mem_allocation finding")
	}
}

func TestReservationExceedsLimit(t *testing.T) {
	s := svc("app")
	s.MemLimit = "512m"
	s.MemReservation = "1g"
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "reservation_exceeds_limit" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected reservation_exceeds_limit finding")
	}
}

func TestNoPidsLimit(t *testing.T) {
	s := svc("worker")
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_pids_limit" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected no_pids_limit finding")
	}
}

func TestWithPidsLimit(t *testing.T) {
	s := svc("worker")
	s.PidsLimit = 100
	s.CPUs = "1.0"
	s.MemLimit = "512m"
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_pids_limit" {
				t.Fatal("should not have no_pids_limit when PidsLimit is set")
			}
		}
	}
}

func TestCleanService(t *testing.T) {
	s := svc("web")
	s.CPUs = "2.0"
	s.MemLimit = "1g"
	s.PidsLimit = 200
	c := collected(s)
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for clean service, got %d", r.Summary.TotalFindings)
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("noisy")
	c := collected(s)
	r := Analyze(c)
	if r.Summary.NoCPULimit < 1 {
		t.Fatal("expected NoCPULimit > 0")
	}
	if r.Summary.NoMemLimit < 1 {
		t.Fatal("expected NoMemLimit > 0")
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("web")
	s1.CPUs = "1.0"
	s1.MemLimit = "512m"
	s1.PidsLimit = 100
	s2 := svc("worker")
	c := collected(s1, s2)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text")
	}
	if !containsStr(text, "0 findings") {
		t.Fatal("expected '0 findings' in output")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	s := svc("app")
	c := collected(s)
	r := Analyze(c)
	text := FormatText(r)
	if !containsStr(text, "app") {
		t.Fatal("expected service name in output")
	}
	if !containsStr(text, "Resource Affinity") {
		t.Fatal("expected header in output")
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
