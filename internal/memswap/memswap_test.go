package memswap

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

func TestUnlimitedSwap(t *testing.T) {
	svc := compose.Service{Name: "app", MemLimit: "512m"}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "memswap_unlimited" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected memswap_unlimited finding for service with mem_limit but no swap limit")
	}
}

func TestSwapDisabled(t *testing.T) {
	svc := compose.Service{Name: "app", MemLimit: "512m", MemswapLimit: "512m"}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "memswap_disabled" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected memswap_disabled finding when swap equals mem limit")
	}
}

func TestExcessiveSwap(t *testing.T) {
	svc := compose.Service{Name: "app", MemLimit: "256m", MemswapLimit: "2g"}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "memswap_excessive" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected memswap_excessive finding when swap > 4x mem limit")
	}
}

func TestPrivilegedUnlimitedSwap(t *testing.T) {
	svc := compose.Service{Name: "agent", MemLimit: "1g", Privileged: true}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "memswap_privileged_unlimited" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected memswap_privileged_unlimited for privileged service")
	}
}

func TestExplicitUnlimited(t *testing.T) {
	svc := compose.Service{Name: "db", MemswapLimit: "-1"}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "memswap_explicit_unlimited" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected memswap_explicit_unlimited for memswap_limit: -1")
	}
}

func TestNoLimits(t *testing.T) {
	svc := compose.Service{Name: "worker"}
	r := Analyze(collected(svc))
	for _, sr := range r.Services {
		if len(sr.Findings) != 0 {
			t.Error("expected no findings for service without memory limits")
		}
	}
}

func TestReasonableSwap(t *testing.T) {
	svc := compose.Service{Name: "web", MemLimit: "512m", MemswapLimit: "1g"}
	r := Analyze(collected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "memswap_excessive" {
				t.Error("unexpected excessive finding for 2x swap ratio")
			}
		}
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"512m", 512 * 1024 * 1024},
		{"1g", 1024 * 1024 * 1024},
		{"256k", 256 * 1024},
		{"1024", 1024},
		{"", 0},
		{"-1", 0},
	}
	for _, tt := range tests {
		got := parseSize(tt.input)
		if got != tt.want {
			t.Errorf("parseSize(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestSummary(t *testing.T) {
	svcs := []compose.Service{
		{Name: "a", MemLimit: "512m"},
		{Name: "b", MemLimit: "256m", MemswapLimit: "256m"},
		{Name: "c"},
	}
	r := Analyze(collected(svcs...))
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.UnlimitedSwap != 1 {
		t.Errorf("expected 1 unlimited, got %d", r.Summary.UnlimitedSwap)
	}
	if r.Summary.SwapDisabled != 1 {
		t.Errorf("expected 1 disabled, got %d", r.Summary.SwapDisabled)
	}
}

func TestFormatText(t *testing.T) {
	svc := compose.Service{Name: "app", MemLimit: "512m"}
	r := Analyze(collected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "Memory Swap") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "mem_limit=512m") {
		t.Error("missing mem_limit in output")
	}
}
