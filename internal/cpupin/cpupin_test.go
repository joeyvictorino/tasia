package cpupin

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

func TestNoPinning(t *testing.T) {
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	if r.Services[0].Pinned {
		t.Error("expected service to not be pinned")
	}
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(r.Services[0].Findings))
	}
}

func TestSingleCorePinning(t *testing.T) {
	c := collected(compose.Service{
		Name:       "worker",
		CpusetCpus: "3",
	})
	r := Analyze(c)
	if !r.Services[0].Pinned {
		t.Error("expected service to be pinned")
	}
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "cpu_pin_single_core" {
			found = true
		}
	}
	if !found {
		t.Error("expected cpu_pin_single_core finding")
	}
}

func TestMultiCorePinning(t *testing.T) {
	c := collected(compose.Service{
		Name:       "worker",
		CpusetCpus: "0-3",
	})
	r := Analyze(c)
	if !r.Services[0].Pinned {
		t.Error("expected service to be pinned")
	}
	for _, f := range r.Services[0].Findings {
		if f.Rule == "cpu_pin_single_core" {
			t.Error("should not flag single core for range 0-3")
		}
	}
}

func TestHighCpuId(t *testing.T) {
	c := collected(compose.Service{
		Name:       "worker",
		CpusetCpus: "0,128",
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "cpu_pin_high_cpu_id" {
			found = true
		}
	}
	if !found {
		t.Error("expected cpu_pin_high_cpu_id finding for CPU 128")
	}
}

func TestContentionDetection(t *testing.T) {
	c := collected(
		compose.Service{Name: "web", CpusetCpus: "0-2"},
		compose.Service{Name: "api", CpusetCpus: "2-4"},
	)
	r := Analyze(c)
	webContention := false
	apiContention := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "cpu_pin_contention" {
				if sr.Service == "web" {
					webContention = true
				}
				if sr.Service == "api" {
					apiContention = true
				}
			}
		}
	}
	if !webContention || !apiContention {
		t.Error("expected contention finding on both overlapping services")
	}
}

func TestNoContention(t *testing.T) {
	c := collected(
		compose.Service{Name: "web", CpusetCpus: "0-1"},
		compose.Service{Name: "api", CpusetCpus: "2-3"},
	)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "cpu_pin_contention" {
				t.Errorf("unexpected contention finding on %s", sr.Service)
			}
		}
	}
}

func TestNumaMemPinning(t *testing.T) {
	c := collected(compose.Service{
		Name:       "worker",
		CpusetCpus: "0-3",
		CpusetMems: "0",
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "cpu_pin_numa_mem" {
			found = true
		}
	}
	if !found {
		t.Error("expected cpu_pin_numa_mem finding")
	}
}

func TestLowCpuShares(t *testing.T) {
	c := collected(compose.Service{
		Name:      "worker",
		CpuShares: 1,
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "cpu_pin_low_shares" {
			found = true
		}
	}
	if !found {
		t.Error("expected cpu_pin_low_shares finding")
	}
}

func TestHighCpuShares(t *testing.T) {
	c := collected(compose.Service{
		Name:      "worker",
		CpuShares: 8192,
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "cpu_pin_high_shares" {
			found = true
		}
	}
	if !found {
		t.Error("expected cpu_pin_high_shares finding")
	}
}

func TestNormalCpuShares(t *testing.T) {
	c := collected(compose.Service{
		Name:      "worker",
		CpuShares: 1024,
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Rule == "cpu_pin_low_shares" || f.Rule == "cpu_pin_high_shares" {
			t.Errorf("unexpected shares finding: %s", f.Rule)
		}
	}
}

func TestSummary(t *testing.T) {
	c := collected(
		compose.Service{Name: "web", CpusetCpus: "0-2"},
		compose.Service{Name: "api", CpusetCpus: "2-4"},
		compose.Service{Name: "db"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.PinnedServices != 2 {
		t.Errorf("expected 2 pinned, got %d", r.Summary.PinnedServices)
	}
	if r.Summary.Contentions == 0 {
		t.Error("expected at least 1 contention")
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{Name: "web", CpusetCpus: "0"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !containsStr(text, "CPU Pinning Audit") {
		t.Error("expected header in text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "web", CpusetCpus: "0-3"})
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

func TestEmptyServices(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstr(s, sub))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
