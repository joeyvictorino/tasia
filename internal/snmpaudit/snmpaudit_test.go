package snmpaudit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, env []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports}
}

func port(raw string, target int) compose.PortMapping {
	return compose.PortMapping{Raw: raw, TargetPort: target}
}

func collected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func findRule(results []ServiceResult, rule string) *Finding {
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return &f
			}
		}
	}
	return nil
}

func TestDefaultCommunityPublic(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", []string{"SNMP_COMMUNITY=public"}, nil)))
	if f := findRule(r.Results, "SNMP-001"); f == nil {
		t.Fatal("expected SNMP-001 for default community 'public'")
	}
}

func TestDefaultCommunityPrivate(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", []string{"COMMUNITY_STRING=Private"}, nil)))
	if f := findRule(r.Results, "SNMP-001"); f == nil {
		t.Fatal("expected SNMP-001 for default community 'Private'")
	}
}

func TestCustomCommunityOK(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", []string{"SNMP_COMMUNITY=x7kQ!9zLm"}, nil)))
	if f := findRule(r.Results, "SNMP-001"); f != nil {
		t.Fatal("should not flag custom community string")
	}
}

func TestSNMPv1(t *testing.T) {
	r := Analyze(collected(svc("snmp", "snmpd-server", []string{"SNMP_VERSION=1"}, nil)))
	if f := findRule(r.Results, "SNMP-002"); f == nil {
		t.Fatal("expected SNMP-002 for v1")
	}
}

func TestSNMPv2c(t *testing.T) {
	r := Analyze(collected(svc("snmp", "snmpd-server", []string{"SNMP_VERSION=v2c"}, nil)))
	if f := findRule(r.Results, "SNMP-002"); f == nil {
		t.Fatal("expected SNMP-002 for v2c")
	}
}

func TestSNMPv3OK(t *testing.T) {
	r := Analyze(collected(svc("snmp", "snmpd-server", []string{"SNMP_VERSION=3"}, nil)))
	if f := findRule(r.Results, "SNMP-002"); f != nil {
		t.Fatal("should not flag v3")
	}
}

func TestDefaultPort161(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", nil, []compose.PortMapping{port("161:161", 161)})))
	if f := findRule(r.Results, "SNMP-003"); f == nil {
		t.Fatal("expected SNMP-003 for port 161")
	}
}

func TestDefaultPort162(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", nil, []compose.PortMapping{port("162:162", 162)})))
	if f := findRule(r.Results, "SNMP-003"); f == nil {
		t.Fatal("expected SNMP-003 for port 162")
	}
}

func TestNonDefaultPort(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", nil, []compose.PortMapping{port("10161:10161", 10161)})))
	if f := findRule(r.Results, "SNMP-003"); f != nil {
		t.Fatal("should not flag non-default port")
	}
}

func TestWriteAccess(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", []string{"WRITE_COMMUNITY=secret"}, nil)))
	if f := findRule(r.Results, "SNMP-004"); f == nil {
		t.Fatal("expected SNMP-004 for write community")
	}
}

func TestNoAuthDisabled(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", []string{"SNMP_AUTH=none"}, nil)))
	if f := findRule(r.Results, "SNMP-005"); f == nil {
		t.Fatal("expected SNMP-005 for auth=none")
	}
}

func TestAuthEnabled(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", []string{"SNMP_AUTH=SHA"}, nil)))
	if f := findRule(r.Results, "SNMP-005"); f != nil {
		t.Fatal("should not flag enabled auth")
	}
}

func TestNoEncryption(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", []string{"SNMP_PRIV=none"}, nil)))
	if f := findRule(r.Results, "SNMP-006"); f == nil {
		t.Fatal("expected SNMP-006 for priv=none")
	}
}

func TestEncryptionEnabled(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", []string{"SNMP_PRIV=AES"}, nil)))
	if f := findRule(r.Results, "SNMP-006"); f != nil {
		t.Fatal("should not flag AES encryption")
	}
}

func TestNonSNMPIgnored(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx:latest", []string{"SNMP_COMMUNITY=public"}, nil)))
	if r.Summary.TotalFindings != 0 {
		t.Fatal("should not flag non-SNMP service")
	}
}

func TestIsSNMPService(t *testing.T) {
	cases := []struct {
		image string
		want  bool
	}{
		{"net-snmp", true},
		{"snmpd-server", true},
		{"snmpsim/simulator", true},
		{"nginx:latest", false},
		{"postgres:15", false},
	}
	for _, c := range cases {
		got := isSNMPService(compose.Service{Image: c.image})
		if got != c.want {
			t.Errorf("isSNMPService(%q) = %v, want %v", c.image, got, c.want)
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	r := Analyze(collected(
		svc("snmp1", "net-snmp", []string{"SNMP_COMMUNITY=public", "SNMP_VERSION=1"}, nil),
		svc("web", "nginx", nil, nil),
	))
	if r.Summary.TotalServices != 2 {
		t.Errorf("TotalServices = %d, want 2", r.Summary.TotalServices)
	}
	if r.Summary.AffectedServices != 1 {
		t.Errorf("AffectedServices = %d, want 1", r.Summary.AffectedServices)
	}
	if r.Summary.TotalFindings != 2 {
		t.Errorf("TotalFindings = %d, want 2", r.Summary.TotalFindings)
	}
}

func TestFormatTextHeader(t *testing.T) {
	r := Analyze(collected())
	text := FormatText(r)
	if !strings.Contains(text, "SNMP Security Audit") {
		t.Error("missing header")
	}
}

func TestFormatJSONValid(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", []string{"SNMP_AUTH=none"}, nil)))
	var out Report
	if err := json.Unmarshal([]byte(FormatJSON(r)), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 || r.Summary.TotalFindings != 0 {
		t.Error("expected empty results for empty collected")
	}
}

func TestMultipleFindings(t *testing.T) {
	r := Analyze(collected(svc("snmp", "net-snmp", []string{
		"SNMP_COMMUNITY=public",
		"SNMP_VERSION=2c",
		"WRITE_COMMUNITY=private",
		"SNMP_AUTH=none",
		"SNMP_PRIV=none",
	}, []compose.PortMapping{port("161:161", 161)})))
	if r.Summary.TotalFindings != 6 {
		t.Errorf("expected 6 findings, got %d", r.Summary.TotalFindings)
	}
}
