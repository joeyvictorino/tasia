package nfsaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
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

func withImage(img string) func(*compose.Service) {
	return func(s *compose.Service) { s.Image = img }
}

func withEnv(envs ...string) func(*compose.Service) {
	return func(s *compose.Service) { s.Environment = append(s.Environment, envs...) }
}

func withPortsFull(ports ...compose.PortMapping) func(*compose.Service) {
	return func(s *compose.Service) { s.Ports = append(s.Ports, ports...) }
}

func withVolumes(vols ...string) func(*compose.Service) {
	return func(s *compose.Service) { s.Volumes = append(s.Volumes, vols...) }
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

func TestWorldReadableExport(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("erichough/nfs-server"), withEnv("NFS_EXPORT=* /data")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-001") == nil {
		t.Fatal("expected NFS-001 for world-readable export")
	}
}

func TestRestrictedExport(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("erichough/nfs-server"), withEnv("NFS_EXPORT=10.0.0.0/24 /data")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-001") != nil {
		t.Fatal("unexpected NFS-001 when export restricted")
	}
}

func TestNoRootSquashOptions(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-server"), withEnv("NFS_EXPORT_OPTIONS=rw,no_root_squash,sync")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-002") == nil {
		t.Fatal("expected NFS-002 for no_root_squash")
	}
}

func TestNoRootSquashEnv(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-server"), withEnv("NO_ROOT_SQUASH=true")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-002") == nil {
		t.Fatal("expected NFS-002 for no_root_squash env")
	}
}

func TestRootSquashDefault(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-server"), withEnv("NFS_EXPORT_OPTIONS=rw,root_squash,sync")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-002") != nil {
		t.Fatal("unexpected NFS-002 when root_squash is default")
	}
}

func TestInsecurePorts(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-server"), withEnv("INSECURE=true")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-003") == nil {
		t.Fatal("expected NFS-003 for insecure ports")
	}
}

func TestSecurePorts(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-server"), withEnv("INSECURE=false")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-003") != nil {
		t.Fatal("unexpected NFS-003 when insecure disabled")
	}
}

func TestMissingKerberos(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-ganesha")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-004") == nil {
		t.Fatal("expected NFS-004 for missing Kerberos")
	}
}

func TestKerberosConfigured(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-ganesha"), withEnv("NFS_KERBEROS=true")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-004") != nil {
		t.Fatal("unexpected NFS-004 when Kerberos configured")
	}
}

func TestKerberosVolumeMount(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-ganesha"), withVolumes("./config/krb5.keytab:/etc/krb5.keytab")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-004") != nil {
		t.Fatal("unexpected NFS-004 when Kerberos keytab mounted")
	}
}

func TestNFSv3NoEncrypt(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-server"), withEnv("NFS_VERSION=3")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-005") == nil {
		t.Fatal("expected NFS-005 for NFS v3 without encryption")
	}
}

func TestNFSv3WithEncrypt(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-server"), withEnv("NFS_VERSION=3", "NFS_ENCRYPTION=stunnel")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-005") != nil {
		t.Fatal("unexpected NFS-005 when encryption configured")
	}
}

func TestNFSv4NoEncryptWarning(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-server"), withEnv("NFS_VERSION=4.2")))
	r := Analyze(c)
	if findRule(r.Results, "NFS-005") != nil {
		t.Fatal("unexpected NFS-005 for NFS v4")
	}
}

func TestExposedPort(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-server"),
		withPortsFull(compose.PortMapping{HostPort: 2049, TargetPort: 2049, Raw: "2049:2049"})))
	r := Analyze(c)
	if findRule(r.Results, "NFS-006") == nil {
		t.Fatal("expected NFS-006 for exposed NFS port")
	}
}

func TestLocalhostPort(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-server"),
		withPortsFull(compose.PortMapping{HostPort: 2049, TargetPort: 2049, Raw: "127.0.0.1:2049:2049", HostIP: "127.0.0.1"})))
	r := Analyze(c)
	if findRule(r.Results, "NFS-006") != nil {
		t.Fatal("unexpected NFS-006 for localhost binding")
	}
}

func TestNonNFSServiceIgnored(t *testing.T) {
	c := mkCollected(svc("web", withImage("nginx:latest")))
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestIsNFSImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"erichough/nfs-server:latest", true},
		{"itsthenetwork/nfs-server-alpine", true},
		{"nfs-ganesha:3.5", true},
		{"nginx:latest", false},
		{"postgres:15", false},
	}
	for _, tt := range tests {
		if got := isNFSImage(tt.image); got != tt.want {
			t.Errorf("isNFSImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-server"),
		withEnv("NFS_EXPORT=* /data", "NFS_EXPORT_OPTIONS=rw,no_root_squash"),
		withPortsFull(compose.PortMapping{HostPort: 2049, TargetPort: 2049, Raw: "2049:2049"})))
	r := Analyze(c)
	if r.Summary.WorldReadable != 1 {
		t.Errorf("expected 1 world readable, got %d", r.Summary.WorldReadable)
	}
	if r.Summary.NoRootSquash != 1 {
		t.Errorf("expected 1 no_root_squash, got %d", r.Summary.NoRootSquash)
	}
	if r.Summary.ExposedPorts != 1 {
		t.Errorf("expected 1 exposed port, got %d", r.Summary.ExposedPorts)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(svc("nfs", withImage("nfs-server")))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "NFS Export Security Audit") {
		t.Fatal("expected header in output")
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/my/project"}
	r := Analyze(c)
	if r.Path != "/my/project" {
		t.Errorf("expected /my/project, got %s", r.Path)
	}
}
