package ulimits

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

func TestNoUlimits(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 1 {
		t.Fatalf("expected 1 finding, got %d", r.Summary.TotalFindings)
	}
	if r.Services[0].Findings[0].RuleID != "ulimit_missing" {
		t.Fatalf("expected ulimit_missing, got %s", r.Services[0].Findings[0].RuleID)
	}
}

func TestUnlimitedMemlock(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Ulimits: map[string]compose.UlimitValue{"memlock": {Soft: -1, Hard: -1}},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "ulimit_unlimited" && f.UlimitName == "memlock" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ulimit_unlimited finding for memlock")
	}
}

func TestUnlimitedCore(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Ulimits: map[string]compose.UlimitValue{"core": {Soft: -1, Hard: -1}},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "ulimit_unlimited" && f.UlimitName == "core" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ulimit_unlimited finding for core")
	}
}

func TestTooHighNofile(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Ulimits: map[string]compose.UlimitValue{"nofile": {Soft: 100000, Hard: 100000}},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "ulimit_too_high" && f.UlimitName == "nofile" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ulimit_too_high for nofile > 65536")
	}
}

func TestTooHighNproc(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Ulimits: map[string]compose.UlimitValue{"nproc": {Soft: 8192, Hard: 8192}},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "ulimit_too_high" && f.UlimitName == "nproc" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ulimit_too_high for nproc > 4096")
	}
}

func TestSafeUlimits(t *testing.T) {
	c := makeCollected(compose.Service{
		Name: "agent",
		Ulimits: map[string]compose.UlimitValue{
			"nofile": {Soft: 1024, Hard: 1024},
			"nproc":  {Soft: 512, Hard: 512},
		},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for safe ulimits, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleServices(t *testing.T) {
	c := makeCollected(
		compose.Service{Name: "safe", Ulimits: map[string]compose.UlimitValue{"nofile": {Soft: 1024, Hard: 1024}}},
		compose.Service{Name: "unsafe"},
	)
	r := Analyze(c)
	if r.Summary.ServicesWithUlimits != 1 {
		t.Fatalf("expected 1 with ulimits, got %d", r.Summary.ServicesWithUlimits)
	}
	if r.Summary.ServicesMissing != 1 {
		t.Fatalf("expected 1 missing, got %d", r.Summary.ServicesMissing)
	}
}

func TestUnlimitedNofileSoft(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Ulimits: map[string]compose.UlimitValue{"nofile": {Soft: -1, Hard: 65536}},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "ulimit_unlimited" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ulimit_unlimited when soft is -1")
	}
}

func TestNonDangerousUnlimited(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Ulimits: map[string]compose.UlimitValue{"sigpending": {Soft: -1, Hard: -1}},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "ulimit_unlimited" {
			t.Fatal("sigpending unlimited should not be flagged")
		}
	}
}

func TestExactThresholdNofile(t *testing.T) {
	c := makeCollected(compose.Service{
		Name:    "agent",
		Ulimits: map[string]compose.UlimitValue{"nofile": {Soft: 65536, Hard: 65536}},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "ulimit_too_high" {
			t.Fatal("nofile at exact threshold should not be flagged as too high")
		}
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected(compose.Service{Name: "agent"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("format text returned empty")
	}
	if !contains(text, "Process Ulimit Audit") {
		t.Fatal("missing header")
	}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatal("expected 0 services for empty input")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
