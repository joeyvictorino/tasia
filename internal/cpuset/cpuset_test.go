package cpuset

import (
	"strings"
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

func TestNoCpuset(t *testing.T) {
	svc := compose.Service{Name: "app"}
	r := Analyze(collected(svc))
	if len(r.Services) == 0 {
		t.Fatal("expected services")
	}
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "cpuset_none" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected cpuset_none finding for unconstrained service")
	}
}

func TestWidePinning(t *testing.T) {
	svc := compose.Service{Name: "worker", CpusetCpus: "0-15"}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "cpuset_wide_pin" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected cpuset_wide_pin for 16 CPUs")
	}
}

func TestPrivilegedWideCpuset(t *testing.T) {
	svc := compose.Service{Name: "gpu", CpusetCpus: "0-7", Privileged: true}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "cpuset_privileged_wide" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected cpuset_privileged_wide for privileged service with 8 CPUs")
	}
}

func TestNarrowCpuset(t *testing.T) {
	svc := compose.Service{Name: "web", CpusetCpus: "0-1"}
	r := Analyze(collected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "cpuset_wide_pin" {
				t.Error("unexpected wide pin finding for narrow cpuset")
			}
		}
	}
}

func TestOverlappingCpus(t *testing.T) {
	svc1 := compose.Service{Name: "app1", CpusetCpus: "0-3"}
	svc2 := compose.Service{Name: "app2", CpusetCpus: "2-5"}
	r := Analyze(collected(svc1, svc2))
	if r.Summary.OverlappingCpus == 0 {
		t.Error("expected overlapping CPU finding")
	}
}

func TestNoOverlap(t *testing.T) {
	svc1 := compose.Service{Name: "app1", CpusetCpus: "0-1"}
	svc2 := compose.Service{Name: "app2", CpusetCpus: "2-3"}
	r := Analyze(collected(svc1, svc2))
	if r.Summary.OverlappingCpus != 0 {
		t.Error("expected no overlap finding")
	}
}

func TestWideMems(t *testing.T) {
	svc := compose.Service{Name: "db", CpusetMems: "0-7"}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "cpuset_wide_mems" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected cpuset_wide_mems for 8 NUMA nodes")
	}
}

func TestParseCpuList(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"0", 1},
		{"0-3", 4},
		{"0,2,4", 3},
		{"0-1,4-5", 4},
		{"", 0},
	}
	for _, tt := range tests {
		got := parseCpuList(tt.input)
		if len(got) != tt.want {
			t.Errorf("parseCpuList(%q) = %d items, want %d", tt.input, len(got), tt.want)
		}
	}
}

func TestSummary(t *testing.T) {
	svc1 := compose.Service{Name: "a"}
	svc2 := compose.Service{Name: "b", CpusetCpus: "0-1"}
	r := Analyze(collected(svc1, svc2))
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.NoCpuset != 1 {
		t.Errorf("expected 1 unconstrained, got %d", r.Summary.NoCpuset)
	}
}

func TestFormatText(t *testing.T) {
	svc := compose.Service{Name: "app", CpusetCpus: "0-3"}
	r := Analyze(collected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "CPU Set Affinity") {
		t.Error("missing header in output")
	}
	if !strings.Contains(text, "app") {
		t.Error("missing service name in output")
	}
}
