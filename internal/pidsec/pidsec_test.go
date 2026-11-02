package pidsec

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

func hasRule(sr ServiceResult, rule string) bool {
	for _, f := range sr.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestNoPidLimit(t *testing.T) {
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "pidsec_no_pid_limit") {
		t.Error("expected pidsec_no_pid_limit for service without pids_limit")
	}
}

func TestWithPidLimit(t *testing.T) {
	c := collected(compose.Service{
		Name:      "web",
		PidsLimit: 512,
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "pidsec_no_pid_limit") {
		t.Error("should not flag pidsec_no_pid_limit with pids_limit set")
	}
}

func TestHighPidLimit(t *testing.T) {
	c := collected(compose.Service{
		Name:      "web",
		PidsLimit: 8192,
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "pidsec_high_pid_limit") {
		t.Error("expected pidsec_high_pid_limit for pids_limit=8192")
	}
}

func TestReasonablePidLimit(t *testing.T) {
	c := collected(compose.Service{
		Name:      "web",
		PidsLimit: 256,
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "pidsec_high_pid_limit") {
		t.Error("should not flag pidsec_high_pid_limit for pids_limit=256")
	}
}

func TestNoInit(t *testing.T) {
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "pidsec_no_init") {
		t.Error("expected pidsec_no_init for service without init:true")
	}
}

func TestWithInit(t *testing.T) {
	c := collected(compose.Service{
		Name: "web",
		Init: true,
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "pidsec_no_init") {
		t.Error("should not flag pidsec_no_init with init:true")
	}
}

func TestSummary(t *testing.T) {
	c := collected(
		compose.Service{Name: "web"},
		compose.Service{Name: "worker"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.NoPidLimit != 2 {
		t.Errorf("expected 2 no_pid_limit findings, got %d", r.Summary.NoPidLimit)
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{
		Name:      "web",
		PidsLimit: 256,
		Init:      true,
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for clean service, got %d", len(r.Services[0].Findings))
	}
}
