package cgroupns

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if len(r.Services) != 0 {
		t.Fatalf("expected 0 services, got %d", len(r.Services))
	}
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestHostCgroupNs(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CgroupNsMode: "host"})
	r := Analyze(c)
	if r.Summary.HostCgroupNs != 1 {
		t.Errorf("expected 1 host cgroup ns, got %d", r.Summary.HostCgroupNs)
	}
	if r.Services[0].Findings[0].RuleID != "cgroupns_host_mode" {
		t.Errorf("expected cgroupns_host_mode, got %s", r.Services[0].Findings[0].RuleID)
	}
	if r.Services[0].Findings[0].Severity != "critical" {
		t.Errorf("expected critical, got %s", r.Services[0].Findings[0].Severity)
	}
}

func TestHostCgroupNsCaseInsensitive(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CgroupNsMode: "Host"})
	r := Analyze(c)
	if r.Summary.HostCgroupNs != 1 {
		t.Errorf("expected 1 host cgroup ns, got %d", r.Summary.HostCgroupNs)
	}
}

func TestPrivateCgroupNsNoFinding(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CgroupNsMode: "private"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for private, got %d", r.Summary.TotalFindings)
	}
}

func TestCustomCgroupParent(t *testing.T) {
	c := collected(compose.Service{Name: "worker", CgroupParent: "/custom/agents"})
	r := Analyze(c)
	if r.Summary.CustomParent != 1 {
		t.Errorf("expected 1 custom parent, got %d", r.Summary.CustomParent)
	}
	if r.Services[0].Findings[0].RuleID != "cgroupns_custom_parent" {
		t.Errorf("expected cgroupns_custom_parent, got %s", r.Services[0].Findings[0].RuleID)
	}
	if r.Services[0].Findings[0].Severity != "medium" {
		t.Errorf("expected medium, got %s", r.Services[0].Findings[0].Severity)
	}
}

func TestRootCgroupParentNoFinding(t *testing.T) {
	c := collected(compose.Service{Name: "worker", CgroupParent: "/"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for root parent, got %d", r.Summary.TotalFindings)
	}
}

func TestMissingPrivatePrivileged(t *testing.T) {
	c := collected(compose.Service{Name: "admin", Privileged: true})
	r := Analyze(c)
	if r.Summary.MissingPrivate != 1 {
		t.Errorf("expected 1 missing private, got %d", r.Summary.MissingPrivate)
	}
	if r.Services[0].Findings[0].RuleID != "cgroupns_missing_private" {
		t.Errorf("expected cgroupns_missing_private, got %s", r.Services[0].Findings[0].RuleID)
	}
	if r.Services[0].Findings[0].Severity != "high" {
		t.Errorf("expected high, got %s", r.Services[0].Findings[0].Severity)
	}
}

func TestMissingPrivateCapSysAdmin(t *testing.T) {
	c := collected(compose.Service{Name: "admin", CapAdd: []string{"SYS_ADMIN"}})
	r := Analyze(c)
	if r.Summary.MissingPrivate != 1 {
		t.Errorf("expected 1 missing private, got %d", r.Summary.MissingPrivate)
	}
}

func TestMissingPrivateCapAll(t *testing.T) {
	c := collected(compose.Service{Name: "admin", CapAdd: []string{"ALL"}})
	r := Analyze(c)
	if r.Summary.MissingPrivate != 1 {
		t.Errorf("expected 1 missing private, got %d", r.Summary.MissingPrivate)
	}
}

func TestMissingPrivateCapSysResource(t *testing.T) {
	c := collected(compose.Service{Name: "admin", CapAdd: []string{"SYS_RESOURCE"}})
	r := Analyze(c)
	if r.Summary.MissingPrivate != 1 {
		t.Errorf("expected 1 missing private, got %d", r.Summary.MissingPrivate)
	}
}

func TestNoFindingNonPrivilegedNoMode(t *testing.T) {
	c := collected(compose.Service{Name: "app"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for normal service, got %d", r.Summary.TotalFindings)
	}
}

func TestPrivilegedWithPrivateNoMissingFinding(t *testing.T) {
	c := collected(compose.Service{Name: "admin", Privileged: true, CgroupNsMode: "private"})
	r := Analyze(c)
	if r.Summary.MissingPrivate != 0 {
		t.Errorf("expected 0 missing private (explicit private set), got %d", r.Summary.MissingPrivate)
	}
}

func TestMultipleFindings(t *testing.T) {
	c := collected(compose.Service{Name: "bad", CgroupNsMode: "host", CgroupParent: "/custom"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 2 {
		t.Errorf("expected 2 findings, got %d", r.Summary.TotalFindings)
	}
	if r.Summary.HostCgroupNs != 1 {
		t.Errorf("expected 1 host, got %d", r.Summary.HostCgroupNs)
	}
	if r.Summary.CustomParent != 1 {
		t.Errorf("expected 1 custom, got %d", r.Summary.CustomParent)
	}
}

func TestMultipleServices(t *testing.T) {
	c := collected(
		compose.Service{Name: "a", CgroupNsMode: "host"},
		compose.Service{Name: "b", CgroupNsMode: "private"},
		compose.Service{Name: "c", Privileged: true},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.HostCgroupNs != 1 {
		t.Errorf("expected 1 host, got %d", r.Summary.HostCgroupNs)
	}
	if r.Summary.MissingPrivate != 1 {
		t.Errorf("expected 1 missing private, got %d", r.Summary.MissingPrivate)
	}
}

func TestServiceResultFields(t *testing.T) {
	c := collected(compose.Service{Name: "svc", CgroupNsMode: "host", CgroupParent: "/my/cgroup"})
	r := Analyze(c)
	sr := r.Services[0]
	if sr.CgroupNsMode != "host" {
		t.Errorf("expected host, got %s", sr.CgroupNsMode)
	}
	if sr.CgroupParent != "/my/cgroup" {
		t.Errorf("expected /my/cgroup, got %s", sr.CgroupParent)
	}
	if sr.File != "docker-compose.yml" {
		t.Errorf("expected docker-compose.yml, got %s", sr.File)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CgroupNsMode: "host"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Cgroup Namespace Isolation Audit") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "agent") {
		t.Error("missing service name")
	}
	if !strings.Contains(text, "cgroupns_host_mode") {
		t.Error("missing rule ID")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	text := FormatText(r)
	if !strings.Contains(text, "Total findings:     0") {
		t.Error("expected 0 findings in output")
	}
}

func TestFormatJSON(t *testing.T) {
	c := collected(compose.Service{Name: "agent", CgroupNsMode: "host"})
	r := Analyze(c)
	out := FormatJSON(r)
	var parsed Report
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(parsed.Services) != 1 {
		t.Errorf("expected 1 service, got %d", len(parsed.Services))
	}
}

func TestIsPrivilegedOrElevated(t *testing.T) {
	tests := []struct {
		name string
		svc  compose.Service
		want bool
	}{
		{"plain", compose.Service{}, false},
		{"privileged", compose.Service{Privileged: true}, true},
		{"cap_all", compose.Service{CapAdd: []string{"ALL"}}, true},
		{"cap_sys_admin", compose.Service{CapAdd: []string{"SYS_ADMIN"}}, true},
		{"cap_sys_resource", compose.Service{CapAdd: []string{"SYS_RESOURCE"}}, true},
		{"cap_net_admin", compose.Service{CapAdd: []string{"NET_ADMIN"}}, false},
		{"cap_mixed", compose.Service{CapAdd: []string{"NET_ADMIN", "SYS_ADMIN"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrivilegedOrElevated(&tt.svc)
			if got != tt.want {
				t.Errorf("isPrivilegedOrElevated(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
