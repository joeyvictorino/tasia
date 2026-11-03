package pidlimit

import (
	"encoding/json"
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
	if !hasRule(r.Services[0], "pidlimit_missing") {
		t.Error("expected pidlimit_missing when no pids_limit set")
	}
	if r.Summary.NoPidLimit != 1 {
		t.Errorf("expected 1 no_pid_limit, got %d", r.Summary.NoPidLimit)
	}
}

func TestUnlimitedPidLimit(t *testing.T) {
	c := collected(compose.Service{Name: "app", PidsLimit: -1})
	r := Analyze(c)
	if !hasRule(r.Services[0], "pidlimit_unlimited") {
		t.Error("expected pidlimit_unlimited for pids_limit: -1")
	}
	if r.Summary.UnlimitedPid != 1 {
		t.Errorf("expected 1 unlimited_pid, got %d", r.Summary.UnlimitedPid)
	}
}

func TestHighPidLimit(t *testing.T) {
	c := collected(compose.Service{Name: "app", PidsLimit: 50000})
	r := Analyze(c)
	if !hasRule(r.Services[0], "pidlimit_high") {
		t.Error("expected pidlimit_high for pids_limit: 50000")
	}
	if r.Summary.HighPidLimit != 1 {
		t.Errorf("expected 1 high_pid_limit, got %d", r.Summary.HighPidLimit)
	}
}

func TestLowPidLimit(t *testing.T) {
	c := collected(compose.Service{Name: "app", PidsLimit: 5})
	r := Analyze(c)
	if !hasRule(r.Services[0], "pidlimit_low") {
		t.Error("expected pidlimit_low for pids_limit: 5")
	}
	if r.Summary.LowPidLimit != 1 {
		t.Errorf("expected 1 low_pid_limit, got %d", r.Summary.LowPidLimit)
	}
}

func TestReasonablePidLimit(t *testing.T) {
	c := collected(compose.Service{Name: "app", PidsLimit: 256})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for reasonable pids_limit: 256, got %d", len(r.Services[0].Findings))
	}
}

func TestPrivilegedNoPidLimit(t *testing.T) {
	c := collected(compose.Service{Name: "agent", Privileged: true})
	r := Analyze(c)
	if !hasRule(r.Services[0], "pidlimit_privileged_no_limit") {
		t.Error("expected pidlimit_privileged_no_limit for privileged container without pids_limit")
	}
}

func TestPrivilegedWithPidLimit(t *testing.T) {
	c := collected(compose.Service{Name: "agent", Privileged: true, PidsLimit: 100})
	r := Analyze(c)
	if hasRule(r.Services[0], "pidlimit_privileged_no_limit") {
		t.Error("should not flag privileged_no_limit when pids_limit is set")
	}
}

func TestBoundaryHighThreshold(t *testing.T) {
	c := collected(compose.Service{Name: "app", PidsLimit: 32768})
	r := Analyze(c)
	if hasRule(r.Services[0], "pidlimit_high") {
		t.Error("pids_limit equal to threshold should not be flagged as high")
	}
}

func TestBoundaryAboveHighThreshold(t *testing.T) {
	c := collected(compose.Service{Name: "app", PidsLimit: 32769})
	r := Analyze(c)
	if !hasRule(r.Services[0], "pidlimit_high") {
		t.Error("pids_limit just above threshold should be flagged as high")
	}
}

func TestBoundaryLowThreshold(t *testing.T) {
	c := collected(compose.Service{Name: "app", PidsLimit: 10})
	r := Analyze(c)
	if hasRule(r.Services[0], "pidlimit_low") {
		t.Error("pids_limit equal to low threshold should not be flagged")
	}
}

func TestMultipleServices(t *testing.T) {
	c := collected(
		compose.Service{Name: "web"},
		compose.Service{Name: "app", PidsLimit: 100},
		compose.Service{Name: "worker", PidsLimit: -1},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.NoPidLimit != 1 {
		t.Errorf("expected 1 no_pid_limit, got %d", r.Summary.NoPidLimit)
	}
	if r.Summary.UnlimitedPid != 1 {
		t.Errorf("expected 1 unlimited_pid, got %d", r.Summary.UnlimitedPid)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "app", PidsLimit: -1})
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Report
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service after round-trip, got %d", r2.Summary.TotalServices)
	}
}
