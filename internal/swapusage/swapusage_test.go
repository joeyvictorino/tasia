package swapusage

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func findRule(results []ServiceResult, rule string) bool {
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return true
			}
		}
	}
	return false
}

func TestUnlimitedSwapMinusOne(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:         "worker",
		MemswapLimit: "-1",
	})
	r := Analyze(c)
	if !findRule(r.Services, "swap_unlimited") {
		t.Error("expected swap_unlimited for memswap_limit=-1")
	}
}

func TestUnlimitedSwapZero(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:         "worker",
		MemswapLimit: "0",
	})
	r := Analyze(c)
	if !findRule(r.Services, "swap_unlimited") {
		t.Error("expected swap_unlimited for memswap_limit=0")
	}
}

func TestLimitedSwapNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:         "worker",
		MemLimit:     "512m",
		MemswapLimit: "1g",
	})
	r := Analyze(c)
	if findRule(r.Services, "swap_unlimited") {
		t.Error("should not flag limited swap")
	}
}

func TestSwapWithoutMemLimit(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:         "worker",
		MemswapLimit: "1g",
	})
	r := Analyze(c)
	if !findRule(r.Services, "swap_no_mem_limit") {
		t.Error("expected swap_no_mem_limit when memswap set without mem_limit")
	}
}

func TestSwapWithMemLimit(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:         "worker",
		MemLimit:     "512m",
		MemswapLimit: "1g",
	})
	r := Analyze(c)
	if findRule(r.Services, "swap_no_mem_limit") {
		t.Error("should not flag swap when mem_limit is also set")
	}
}

func TestHighSwappiness100(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Sysctls: map[string]string{"vm.swappiness": "100"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "swap_high_swappiness") {
		t.Error("expected swap_high_swappiness for vm.swappiness=100")
	}
}

func TestHighSwappiness90(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Sysctls: map[string]string{"vm.swappiness": "90"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "swap_high_swappiness") {
		t.Error("expected swap_high_swappiness for vm.swappiness=90")
	}
}

func TestNormalSwappiness(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Sysctls: map[string]string{"vm.swappiness": "60"},
	})
	r := Analyze(c)
	if findRule(r.Services, "swap_high_swappiness") {
		t.Error("should not flag normal swappiness")
	}
}

func TestSwapEqualsMem(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:         "worker",
		MemLimit:     "512m",
		MemswapLimit: "512m",
	})
	r := Analyze(c)
	if !findRule(r.Services, "swap_equals_mem") {
		t.Error("expected swap_equals_mem when limits are equal")
	}
}

func TestSwapNotEqualsMem(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:         "worker",
		MemLimit:     "512m",
		MemswapLimit: "1g",
	})
	r := Analyze(c)
	if findRule(r.Services, "swap_equals_mem") {
		t.Error("should not flag different limits")
	}
}

func TestSwapEnvExposed(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"SWAP_SIZE=2g"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "swap_env_exposed") {
		t.Error("expected swap_env_exposed for SWAP env var")
	}
}

func TestSwapEnvFromVar(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"SWAP_SIZE=${SWAP_VAL}"},
	})
	r := Analyze(c)
	if findRule(r.Services, "swap_env_exposed") {
		t.Error("should not flag env var reference")
	}
}

func TestSwapEnvNoSwapKeyword(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"APP_MEM=512m"},
	})
	r := Analyze(c)
	if findRule(r.Services, "swap_env_exposed") {
		t.Error("should not flag non-swap env var")
	}
}

func TestPrivilegedUnlimitedSwap(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:         "worker",
		Privileged:   true,
		MemswapLimit: "-1",
	})
	r := Analyze(c)
	if !findRule(r.Services, "swap_privileged_unlimited") {
		t.Error("expected swap_privileged_unlimited for privileged + unlimited swap")
	}
}

func TestPrivilegedLimitedSwap(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:         "worker",
		Privileged:   true,
		MemLimit:     "512m",
		MemswapLimit: "1g",
	})
	r := Analyze(c)
	if findRule(r.Services, "swap_privileged_unlimited") {
		t.Error("should not flag privileged with limited swap")
	}
}

func TestNoSwapConfigNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleServices(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "web"},
		compose.Service{Name: "worker", MemswapLimit: "-1"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "worker", MemswapLimit: "-1", Privileged: true},
	)
	r := Analyze(c)
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{Name: "worker", MemswapLimit: "-1"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Swap Usage") {
		t.Error("expected 'Swap Usage' in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "no findings") {
		t.Error("expected 'no findings' in output")
	}
}

func TestReportPath(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.Path)
	}
}

func TestHighSwappiness80(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Sysctls: map[string]string{"vm.swappiness": "80"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "swap_high_swappiness") {
		t.Error("expected swap_high_swappiness for vm.swappiness=80")
	}
}
