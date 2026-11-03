package swaplimit

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

func TestNoLimits(t *testing.T) {
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "swaplimit_no_mem_limit") {
		t.Error("expected swaplimit_no_mem_limit when no limits set")
	}
	if r.Summary.NoMemLimit != 1 {
		t.Errorf("expected 1 no_mem_limit, got %d", r.Summary.NoMemLimit)
	}
}

func TestMemLimitNoSwap(t *testing.T) {
	c := collected(compose.Service{Name: "web", MemLimit: "512m"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "swaplimit_no_swap_limit") {
		t.Error("expected swaplimit_no_swap_limit when mem_limit set without memswap_limit")
	}
	if r.Summary.NoSwapLimit != 1 {
		t.Errorf("expected 1 no_swap_limit, got %d", r.Summary.NoSwapLimit)
	}
}

func TestUnlimitedSwap(t *testing.T) {
	c := collected(compose.Service{Name: "app", MemLimit: "1g", MemswapLimit: "-1"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "swaplimit_unlimited") {
		t.Error("expected swaplimit_unlimited for memswap_limit: -1")
	}
	if r.Summary.UnlimitedSwap != 1 {
		t.Errorf("expected 1 unlimited_swap, got %d", r.Summary.UnlimitedSwap)
	}
}

func TestSwapExceedsMemory(t *testing.T) {
	c := collected(compose.Service{Name: "app", MemLimit: "512m", MemswapLimit: "2g"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "swaplimit_exceeds_memory") {
		t.Error("expected swaplimit_exceeds_memory when swap > 2x memory")
	}
	if r.Summary.SwapExceedsMemory != 1 {
		t.Errorf("expected 1 swap_exceeds_memory, got %d", r.Summary.SwapExceedsMemory)
	}
}

func TestReasonableSwap(t *testing.T) {
	c := collected(compose.Service{Name: "app", MemLimit: "512m", MemswapLimit: "768m"})
	r := Analyze(c)
	if hasRule(r.Services[0], "swaplimit_exceeds_memory") {
		t.Error("swap within 2x memory should not be flagged")
	}
	if hasRule(r.Services[0], "swaplimit_unlimited") {
		t.Error("should not flag unlimited for explicit limit")
	}
	if hasRule(r.Services[0], "swaplimit_no_swap_limit") {
		t.Error("should not flag no_swap_limit when memswap_limit is set")
	}
}

func TestSwapEqualToDoubleMemory(t *testing.T) {
	c := collected(compose.Service{Name: "app", MemLimit: "512m", MemswapLimit: "1024m"})
	r := Analyze(c)
	if hasRule(r.Services[0], "swaplimit_exceeds_memory") {
		t.Error("swap equal to 2x memory should not be flagged (only > 2x)")
	}
}

func TestPrivilegedNoLimits(t *testing.T) {
	c := collected(compose.Service{Name: "agent", Privileged: true})
	r := Analyze(c)
	if !hasRule(r.Services[0], "swaplimit_privileged_no_limit") {
		t.Error("expected swaplimit_privileged_no_limit for privileged without limits")
	}
}

func TestPrivilegedWithLimits(t *testing.T) {
	c := collected(compose.Service{Name: "agent", Privileged: true, MemLimit: "1g", MemswapLimit: "1g"})
	r := Analyze(c)
	if hasRule(r.Services[0], "swaplimit_privileged_no_limit") {
		t.Error("should not flag privileged_no_limit when limits are set")
	}
}

func TestParseSizeBytes(t *testing.T) {
	if parseSize("1024") != 1024 {
		t.Errorf("expected 1024, got %d", parseSize("1024"))
	}
}

func TestParseSizeKB(t *testing.T) {
	if parseSize("1k") != 1024 {
		t.Errorf("expected 1024, got %d", parseSize("1k"))
	}
}

func TestParseSizeMB(t *testing.T) {
	if parseSize("1m") != 1024*1024 {
		t.Errorf("expected %d, got %d", 1024*1024, parseSize("1m"))
	}
}

func TestParseSizeGB(t *testing.T) {
	if parseSize("2g") != 2*1024*1024*1024 {
		t.Errorf("expected %d, got %d", 2*1024*1024*1024, parseSize("2g"))
	}
}

func TestMultipleServices(t *testing.T) {
	c := collected(
		compose.Service{Name: "web"},
		compose.Service{Name: "app", MemLimit: "512m"},
		compose.Service{Name: "worker", MemLimit: "1g", MemswapLimit: "-1"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.NoMemLimit != 1 {
		t.Errorf("expected 1 no_mem_limit, got %d", r.Summary.NoMemLimit)
	}
	if r.Summary.NoSwapLimit != 1 {
		t.Errorf("expected 1 no_swap_limit, got %d", r.Summary.NoSwapLimit)
	}
	if r.Summary.UnlimitedSwap != 1 {
		t.Errorf("expected 1 unlimited_swap, got %d", r.Summary.UnlimitedSwap)
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
	c := collected(compose.Service{Name: "web", MemLimit: "512m"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "app", MemLimit: "1g", MemswapLimit: "-1"})
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
