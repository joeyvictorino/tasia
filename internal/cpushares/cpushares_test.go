package cpushares

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

func TestNoSharesSet(t *testing.T) {
	c := collected(compose.Service{Name: "agent"})
	r := Analyze(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	if len(r.Services[0].Findings) == 0 {
		t.Fatal("expected finding for unset cpu_shares")
	}
	if r.Services[0].Findings[0].Rule != "cpu_shares_unset" {
		t.Errorf("expected cpu_shares_unset, got %s", r.Services[0].Findings[0].Rule)
	}
}

func TestExcessiveShares(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CpuShares: 8192})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "cpu_shares_excessive" {
			found = true
			if f.Level != "high" {
				t.Errorf("expected high, got %s", f.Level)
			}
		}
	}
	if !found {
		t.Error("expected cpu_shares_excessive finding")
	}
}

func TestStarvedShares(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CpuShares: 64})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "cpu_shares_starved" {
			found = true
		}
	}
	if !found {
		t.Error("expected cpu_shares_starved finding")
	}
}

func TestDefaultShares(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CpuShares: 1024})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "cpu_shares_default" {
			found = true
		}
	}
	if !found {
		t.Error("expected cpu_shares_default finding")
	}
}

func TestNormalShares(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CpuShares: 512})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for normal shares, got %d", len(r.Services[0].Findings))
	}
}

func TestSummary(t *testing.T) {
	c := collected(
		compose.Service{Name: "agent1"},
		compose.Service{Name: "agent2", CpuShares: 8192},
		compose.Service{Name: "db", CpuShares: 64},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("total services = %d", r.Summary.TotalServices)
	}
	if r.Summary.NoShares != 1 {
		t.Errorf("no shares = %d", r.Summary.NoShares)
	}
	if r.Summary.HighShares != 1 {
		t.Errorf("high shares = %d", r.Summary.HighShares)
	}
	if r.Summary.LowShares != 1 {
		t.Errorf("low shares = %d", r.Summary.LowShares)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CpuShares: 8192})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("empty text output")
	}
}

func TestJSON(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CpuShares: 8192})
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Services) != 1 {
		t.Errorf("services = %d", len(parsed.Services))
	}
}
