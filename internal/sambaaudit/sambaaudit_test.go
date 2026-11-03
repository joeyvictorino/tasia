package sambaaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func svc(name string, opts ...func(*compose.Service)) compose.Service {
	s := compose.Service{Name: name}
	for _, o := range opts {
		o(&s)
	}
	return s
}

func withEnv(envs ...string) func(*compose.Service) {
	return func(s *compose.Service) { s.Environment = append(s.Environment, envs...) }
}

func withImage(img string) func(*compose.Service) {
	return func(s *compose.Service) { s.Image = img }
}

func withPorts(ports ...compose.PortMapping) func(*compose.Service) {
	return func(s *compose.Service) { s.Ports = append(s.Ports, ports...) }
}

func findRule(results []ServiceResult, ruleID string) *Finding {
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Rule == ruleID {
				return &f
			}
		}
	}
	return nil
}

func TestGuestAccessEnabled(t *testing.T) {
	c := mkCollected(svc("smb", withImage("dperson/samba"), withEnv("GUEST_ACCESS=true")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-001") == nil {
		t.Fatal("expected SMB-001 for guest access")
	}
}

func TestGuestAccessBadUser(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("MAP_TO_GUEST=Bad User")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-001") == nil {
		t.Fatal("expected SMB-001 for bad user mapping")
	}
}

func TestGuestAccessDisabled(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("GUEST_ACCESS=false")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-001") != nil {
		t.Fatal("unexpected SMB-001 when guest disabled")
	}
}

func TestNullSessionEnabled(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("NULL_SESSION=true")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-002") == nil {
		t.Fatal("expected SMB-002 for null session")
	}
}

func TestNullSessionDisabled(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("NULL_SESSION=false")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-002") != nil {
		t.Fatal("unexpected SMB-002 when null session disabled")
	}
}

func TestSMBv1Allowed(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("SMB_MIN_PROTOCOL=NT1")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-003") == nil {
		t.Fatal("expected SMB-003 for SMBv1")
	}
}

func TestSMBv1Lanman(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("MIN_PROTOCOL=LANMAN1")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-003") == nil {
		t.Fatal("expected SMB-003 for LANMAN1")
	}
}

func TestSMBv3Safe(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("SMB_MIN_PROTOCOL=SMB3")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-003") != nil {
		t.Fatal("unexpected SMB-003 for SMB3")
	}
}

func TestEncryptionDisabled(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("SMB_ENCRYPT=disabled")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-004") == nil {
		t.Fatal("expected SMB-004 for disabled encryption")
	}
}

func TestEncryptionEnabled(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("SMB_ENCRYPT=required")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-004") != nil {
		t.Fatal("unexpected SMB-004 when encryption enabled")
	}
}

func TestDefaultPort445(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"),
		withPorts(compose.PortMapping{TargetPort: 445, Raw: "445:445"})))
	r := Analyze(c)
	if findRule(r.Results, "SMB-005") == nil {
		t.Fatal("expected SMB-005 for port 445")
	}
}

func TestDefaultPort139(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"),
		withPorts(compose.PortMapping{TargetPort: 139, Raw: "139:139"})))
	r := Analyze(c)
	if findRule(r.Results, "SMB-005") == nil {
		t.Fatal("expected SMB-005 for port 139")
	}
}

func TestNonDefaultPort(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"),
		withPorts(compose.PortMapping{TargetPort: 9445, Raw: "9445:9445"})))
	r := Analyze(c)
	if findRule(r.Results, "SMB-005") != nil {
		t.Fatal("unexpected SMB-005 for non-default port")
	}
}

func TestWorldWritable(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("WRITABLE=true")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-006") == nil {
		t.Fatal("expected SMB-006 for writable share")
	}
}

func TestReadOnlyFalse(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("READ_ONLY=false")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-006") == nil {
		t.Fatal("expected SMB-006 for read_only=false")
	}
}

func TestReadOnlyTrue(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("READ_ONLY=true")))
	r := Analyze(c)
	if findRule(r.Results, "SMB-006") != nil {
		t.Fatal("unexpected SMB-006 when read_only=true")
	}
}

func TestNonSambaIgnored(t *testing.T) {
	c := mkCollected(svc("db", withImage("postgres:15")))
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestIsSambaService(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"dperson/samba", true},
		{"samba-server:latest", true},
		{"custom/smbd", true},
		{"cifs-utils", true},
		{"postgres:15", false},
		{"nginx:latest", false},
	}
	for _, tt := range tests {
		s := compose.Service{Image: tt.image}
		if got := isSambaService(s); got != tt.want {
			t.Errorf("isSambaService(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	c := mkCollected(
		svc("smb", withImage("samba-server"), withEnv("GUEST_ACCESS=true", "NULL_SESSION=true")),
		svc("db", withImage("postgres:15")),
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.AffectedServices != 1 {
		t.Fatalf("expected 1 affected, got %d", r.Summary.AffectedServices)
	}
	if r.Summary.TotalFindings != 2 {
		t.Fatalf("expected 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server"), withEnv("GUEST_ACCESS=true")))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Samba/SMB") {
		t.Fatal("expected header in text output")
	}
}

func TestFormatJSONValid(t *testing.T) {
	c := mkCollected(svc("smb", withImage("samba-server")))
	r := Analyze(c)
	j := FormatJSON(r)
	if !strings.Contains(j, "Results") {
		t.Fatal("expected Results in JSON")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := mkCollected()
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}
