package snmpaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func snmpSvc(name string, envs []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{
		Name:        name,
		Image:       "polinux/snmpd:latest",
		Environment: envs,
		Ports:       ports,
	}
}

func TestNonSnmpImage(t *testing.T) {
	c := makeCollected(compose.Service{Name: "redis", Image: "redis:7"})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for non-snmp image, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestDefaultCommunityPublic(t *testing.T) {
	c := makeCollected(snmpSvc("snmp1", []string{"SNMP_COMMUNITY=public"}, nil))
	r := Analyze(c)
	if r.Summary.DefaultCommunity != 1 {
		t.Fatalf("expected 1 default community, got %d", r.Summary.DefaultCommunity)
	}
}

func TestDefaultCommunityPrivate(t *testing.T) {
	c := makeCollected(snmpSvc("snmp1", []string{"ROCOMMUNITY=private"}, nil))
	r := Analyze(c)
	if r.Summary.DefaultCommunity != 1 {
		t.Fatalf("expected 1 default community, got %d", r.Summary.DefaultCommunity)
	}
}

func TestCustomCommunity(t *testing.T) {
	c := makeCollected(snmpSvc("snmp1", []string{"SNMP_COMMUNITY=xK9m2pQ7rL3s"}, nil))
	r := Analyze(c)
	if r.Summary.DefaultCommunity != 0 {
		t.Fatalf("expected 0 default community for custom string, got %d", r.Summary.DefaultCommunity)
	}
}

func TestSNMPv1v2Warning(t *testing.T) {
	c := makeCollected(snmpSvc("snmp1", []string{"SNMP_VERSION=snmpv2c", "ROCOMMUNITY=secret123"}, nil))
	r := Analyze(c)
	if r.Summary.SNMPv1v2 != 1 {
		t.Fatalf("expected 1 snmpv1v2 finding, got %d", r.Summary.SNMPv1v2)
	}
}

func TestSNMPv3NoWarning(t *testing.T) {
	c := makeCollected(snmpSvc("snmp1", []string{"SNMPV3_USER=admin", "AUTH_PROTOCOL=SHA"}, nil))
	r := Analyze(c)
	if r.Summary.SNMPv1v2 != 0 {
		t.Fatalf("expected 0 snmpv1v2 findings with v3, got %d", r.Summary.SNMPv1v2)
	}
}

func TestExposedPort161(t *testing.T) {
	ports := []compose.PortMapping{{TargetPort: 161, HostPort: 161, Raw: "161:161"}}
	c := makeCollected(snmpSvc("snmp1", nil, ports))
	r := Analyze(c)
	if r.Summary.ExposedPorts != 1 {
		t.Fatalf("expected 1 exposed port, got %d", r.Summary.ExposedPorts)
	}
}

func TestExposedPort162(t *testing.T) {
	ports := []compose.PortMapping{{TargetPort: 162, HostPort: 162, Raw: "162:162"}}
	c := makeCollected(snmpSvc("snmp1", nil, ports))
	r := Analyze(c)
	if r.Summary.ExposedPorts != 1 {
		t.Fatalf("expected 1 exposed port for trap port, got %d", r.Summary.ExposedPorts)
	}
}

func TestLocalhostPortNotExposed(t *testing.T) {
	ports := []compose.PortMapping{{TargetPort: 161, HostPort: 161, HostIP: "127.0.0.1", Raw: "127.0.0.1:161:161"}}
	c := makeCollected(snmpSvc("snmp1", nil, ports))
	r := Analyze(c)
	if r.Summary.ExposedPorts != 0 {
		t.Fatalf("expected 0 exposed ports for localhost, got %d", r.Summary.ExposedPorts)
	}
}

func TestNoAuth(t *testing.T) {
	c := makeCollected(snmpSvc("snmp1", nil, nil))
	r := Analyze(c)
	if r.Summary.NoAuth != 1 {
		t.Fatalf("expected 1 no_auth, got %d", r.Summary.NoAuth)
	}
}

func TestNoAuthWithV3(t *testing.T) {
	c := makeCollected(snmpSvc("snmp1", []string{"SNMPV3_USER=admin", "AUTH_PROTOCOL=SHA"}, nil))
	r := Analyze(c)
	if r.Summary.NoAuth != 0 {
		t.Fatalf("expected 0 no_auth with v3, got %d", r.Summary.NoAuth)
	}
}

func TestWriteAccess(t *testing.T) {
	c := makeCollected(snmpSvc("snmp1", []string{"RWCOMMUNITY=secret123"}, nil))
	r := Analyze(c)
	if r.Summary.WriteAccess != 1 {
		t.Fatalf("expected 1 write access, got %d", r.Summary.WriteAccess)
	}
}

func TestNoWriteAccess(t *testing.T) {
	c := makeCollected(snmpSvc("snmp1", []string{"ROCOMMUNITY=secret123"}, nil))
	r := Analyze(c)
	if r.Summary.WriteAccess != 0 {
		t.Fatalf("expected 0 write access with read-only, got %d", r.Summary.WriteAccess)
	}
}

func TestMissingACL(t *testing.T) {
	c := makeCollected(snmpSvc("snmp1", nil, nil))
	r := Analyze(c)
	if r.Summary.MissingACL != 1 {
		t.Fatalf("expected 1 missing ACL, got %d", r.Summary.MissingACL)
	}
}

func TestACLConfigured(t *testing.T) {
	c := makeCollected(snmpSvc("snmp1", []string{"SNMPD_CONF=com2sec readonly default secret123"}, nil))
	r := Analyze(c)
	if r.Summary.MissingACL != 0 {
		t.Fatalf("expected 0 missing ACL with com2sec, got %d", r.Summary.MissingACL)
	}
}

func TestIsSnmpImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"polinux/snmpd:latest", true},
		{"net-snmp:5", true},
		{"prom/snmp-exporter:latest", true},
		{"nginx:latest", false},
		{"redis:7", false},
	}
	for _, tt := range tests {
		if got := isSnmpImage(tt.image); got != tt.want {
			t.Errorf("isSnmpImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestFormatTextHeader(t *testing.T) {
	c := makeCollected(snmpSvc("snmp1", nil, nil))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "SNMP Security Audit") {
		t.Fatal("expected header in text output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/empty"})
	text := FormatText(r)
	if !strings.Contains(text, "0 findings") {
		t.Fatal("expected zero findings in empty report")
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/my/project"}
	r := Analyze(c)
	if r.Path != "/my/project" {
		t.Errorf("expected path /my/project, got %s", r.Path)
	}
}

func TestSecureConfig(t *testing.T) {
	envs := []string{
		"SNMPV3_USER=monitor",
		"AUTH_PROTOCOL=SHA256",
		"PRIV_PROTOCOL=AES256",
		"SNMPD_CONF=com2sec readonly 10.0.0.0/24 secret",
	}
	ports := []compose.PortMapping{{TargetPort: 161, HostPort: 161, HostIP: "127.0.0.1", Raw: "127.0.0.1:161:161"}}
	c := makeCollected(snmpSvc("snmp1", envs, ports))
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings for secure config, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleServices(t *testing.T) {
	svc1 := snmpSvc("snmp1", []string{"SNMP_COMMUNITY=public"}, nil)
	svc2 := snmpSvc("snmp2", []string{"SNMPV3_USER=admin", "AUTH_PROTOCOL=SHA", "SNMPD_CONF=com2sec readonly default x"}, nil)
	c := makeCollected(svc1, svc2)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.DefaultCommunity != 1 {
		t.Errorf("expected 1 default community, got %d", r.Summary.DefaultCommunity)
	}
}
