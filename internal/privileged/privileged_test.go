package privileged

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}},
	}
}

func TestEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestPrivilegedMode(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "db", Privileged: true, PrivLine: 5}))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "privileged_mode" && f.Severity == "critical" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected privileged_mode finding")
	}
	if r.Summary.PrivilegedCount != 1 {
		t.Fatalf("expected 1 privileged, got %d", r.Summary.PrivilegedCount)
	}
}

func TestDangerousCapAdd(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "app", CapAdd: []string{"SYS_ADMIN", "NET_RAW"}, CapDrop: []string{"ALL"}}))
	count := 0
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "dangerous_cap_add" {
				count++
			}
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 dangerous_cap_add findings, got %d", count)
	}
}

func TestNoCapDropAll(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "web"}))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "no_cap_drop_all" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected no_cap_drop_all finding")
	}
	if r.Summary.NoCapDropAll != 1 {
		t.Fatalf("expected 1 no_cap_drop_all, got %d", r.Summary.NoCapDropAll)
	}
}

func TestCapDropAllSuppresses(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "web", CapDrop: []string{"ALL"}}))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "no_cap_drop_all" {
				t.Fatal("should not flag no_cap_drop_all when ALL is dropped")
			}
		}
	}
	if r.Summary.NoCapDropAll != 0 {
		t.Fatalf("expected 0, got %d", r.Summary.NoCapDropAll)
	}
}

func TestReadWriteRootfs(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "app"}))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "read_write_rootfs" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected read_write_rootfs finding")
	}
}

func TestReadOnlySuppress(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "app", ReadOnly: true, CapDrop: []string{"ALL"}}))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "read_write_rootfs" {
				t.Fatal("should not flag read_write_rootfs when read_only is true")
			}
		}
	}
}

func TestPrivilegedSkipsCapAndRW(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "gpu", Privileged: true, PrivLine: 3}))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.RuleID == "no_cap_drop_all" || f.RuleID == "read_write_rootfs" {
				t.Fatalf("privileged should suppress %s", f.RuleID)
			}
		}
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(col(
		compose.Service{Name: "safe", CapDrop: []string{"ALL"}, ReadOnly: true},
		compose.Service{Name: "risky", Privileged: true, PrivLine: 10},
	))
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.PrivilegedCount != 1 {
		t.Fatalf("expected 1 privileged, got %d", r.Summary.PrivilegedCount)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(col(compose.Service{Name: "db", Privileged: true, PrivLine: 5}))
	out := FormatText(r)
	if !strings.Contains(out, "Privileged Mode Analysis") {
		t.Fatal("expected header")
	}
	if !strings.Contains(out, "privileged_mode") {
		t.Fatal("expected privileged_mode in output")
	}
}

func TestSummaryTotals(t *testing.T) {
	r := Analyze(col(
		compose.Service{Name: "a"},
		compose.Service{Name: "b", CapDrop: []string{"ALL"}, ReadOnly: true},
	))
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for service a")
	}
}
