package ftpaudit

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
	return func(s *compose.Service) {
		s.Environment = append(s.Environment, envs...)
	}
}

func withImage(img string) func(*compose.Service) {
	return func(s *compose.Service) {
		s.Image = img
	}
}

func withPorts(ports ...string) func(*compose.Service) {
	return func(s *compose.Service) {
		for _, p := range ports {
			s.Ports = append(s.Ports, compose.PortMapping{Raw: p})
		}
	}
}

func withVolumes(vols ...string) func(*compose.Service) {
	return func(s *compose.Service) {
		s.Volumes = append(s.Volumes, vols...)
	}
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

func TestAnonymousLoginEnabled(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd"), withEnv("FTP_ANONYMOUS=true")))
	r := Analyze(c)
	if findRule(r.Results, "FTP-001") == nil {
		t.Fatal("expected FTP-001 for anonymous login")
	}
}

func TestAnonymousLoginDisabled(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd"), withEnv("FTP_ANONYMOUS=false")))
	r := Analyze(c)
	if findRule(r.Results, "FTP-001") != nil {
		t.Fatal("unexpected FTP-001 when anonymous disabled")
	}
}

func TestPlaintextPort(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd"), withPorts("21:21")))
	r := Analyze(c)
	if findRule(r.Results, "FTP-002") == nil {
		t.Fatal("expected FTP-002 for plaintext FTP")
	}
}

func TestFTPSPortPresent(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd"), withPorts("21:21", "990:990")))
	r := Analyze(c)
	if findRule(r.Results, "FTP-002") != nil {
		t.Fatal("unexpected FTP-002 when FTPS port present")
	}
}

func TestNoTLSConfig(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("proftpd")))
	r := Analyze(c)
	if findRule(r.Results, "FTP-003") == nil {
		t.Fatal("expected FTP-003 for missing TLS")
	}
}

func TestTLSConfigured(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd"), withEnv("SSL_ENABLE=true")))
	r := Analyze(c)
	if findRule(r.Results, "FTP-003") != nil {
		t.Fatal("unexpected FTP-003 when SSL configured")
	}
}

func TestTLSCertVolume(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd"), withVolumes("./certs:/etc/ssl/certs")))
	r := Analyze(c)
	if findRule(r.Results, "FTP-003") != nil {
		t.Fatal("unexpected FTP-003 when cert volume mounted")
	}
}

func TestWritableAnonymous(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd"), withEnv("ANON_UPLOAD_ENABLE=true")))
	r := Analyze(c)
	if findRule(r.Results, "FTP-004") == nil {
		t.Fatal("expected FTP-004 for writable anonymous")
	}
}

func TestPassivePortRange(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd"), withPorts("21:21")))
	r := Analyze(c)
	if findRule(r.Results, "FTP-005") == nil {
		t.Fatal("expected FTP-005 for missing passive port range")
	}
}

func TestPassivePortRangeConfigured(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd"), withPorts("21:21"), withEnv("PASV_MIN_PORT=30000")))
	r := Analyze(c)
	if findRule(r.Results, "FTP-005") != nil {
		t.Fatal("unexpected FTP-005 when passive ports configured")
	}
}

func TestDefaultCredentials(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd:latest")))
	r := Analyze(c)
	if findRule(r.Results, "FTP-006") == nil {
		t.Fatal("expected FTP-006 for default credentials")
	}
}

func TestCredentialsConfigured(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd"), withEnv("FTP_USER=admin", "FTP_PASSWORD=secret")))
	r := Analyze(c)
	if findRule(r.Results, "FTP-006") != nil {
		t.Fatal("unexpected FTP-006 when credentials configured")
	}
}

func TestNonFTPServiceIgnored(t *testing.T) {
	c := mkCollected(svc("postgres", withImage("postgres:15")))
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestSummaryAffectedCount(t *testing.T) {
	c := mkCollected(
		svc("ftp", withImage("vsftpd"), withEnv("FTP_ANONYMOUS=true")),
		svc("db", withImage("postgres:15")),
	)
	r := Analyze(c)
	if r.Summary.AffectedServices != 1 {
		t.Fatalf("expected 1 affected, got %d", r.Summary.AffectedServices)
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd"), withEnv("FTP_ANONYMOUS=true")))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "FTP Server") {
		t.Fatal("expected header in text output")
	}
}

func TestFormatJSONValid(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd")))
	r := Analyze(c)
	j := FormatJSON(r)
	if !strings.Contains(j, "Results") {
		t.Fatal("expected Results in JSON")
	}
}

func TestMultipleFindings(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("vsftpd"),
		withEnv("FTP_ANONYMOUS=true", "ANON_UPLOAD_ENABLE=true"),
		withPorts("21:21"),
	))
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Fatalf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestProFTPDDetected(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("proftpd:latest")))
	r := Analyze(c)
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for proftpd")
	}
}

func TestPureFTPDDetected(t *testing.T) {
	c := mkCollected(svc("ftp", withImage("pure-ftpd:latest")))
	r := Analyze(c)
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for pure-ftpd")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := mkCollected()
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}
