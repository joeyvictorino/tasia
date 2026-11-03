package ftpaudit

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

func TestAnonymousEnabled(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", []string{"ANONYMOUS_ENABLE=true"}, nil)))
	if f := findRule(r.Results, "FTP-001"); f == nil {
		t.Fatal("expected FTP-001 for anonymous access")
	}
}

func TestAnonymousDisabled(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", []string{"ANONYMOUS_ENABLE=false"}, nil)))
	if f := findRule(r.Results, "FTP-001"); f != nil {
		t.Fatal("should not flag disabled anonymous access")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", []string{"SSL_ENABLE=false"}, nil)))
	if f := findRule(r.Results, "FTP-002"); f == nil {
		t.Fatal("expected FTP-002 for TLS disabled")
	}
}

func TestTLSEnabled(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", []string{"SSL_ENABLE=true"}, nil)))
	if f := findRule(r.Results, "FTP-002"); f != nil {
		t.Fatal("should not flag enabled TLS")
	}
}

func TestDefaultPort21(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", nil, []compose.PortMapping{port("21:21", 21)})))
	if f := findRule(r.Results, "FTP-003"); f == nil {
		t.Fatal("expected FTP-003 for port 21")
	}
}

func TestDefaultPort20(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", nil, []compose.PortMapping{port("20:20", 20)})))
	if f := findRule(r.Results, "FTP-003"); f == nil {
		t.Fatal("expected FTP-003 for port 20")
	}
}

func TestNonDefaultPort(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", nil, []compose.PortMapping{port("2121:2121", 2121)})))
	if f := findRule(r.Results, "FTP-003"); f != nil {
		t.Fatal("should not flag non-default port")
	}
}

func TestWriteEnabled(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", []string{"WRITE_ENABLE=yes"}, nil)))
	if f := findRule(r.Results, "FTP-004"); f == nil {
		t.Fatal("expected FTP-004 for write enabled")
	}
}

func TestWriteDisabled(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", []string{"WRITE_ENABLE=no"}, nil)))
	if f := findRule(r.Results, "FTP-004"); f != nil {
		t.Fatal("should not flag disabled write")
	}
}

func TestWeakUsername(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", []string{"FTP_USER=admin"}, nil)))
	if f := findRule(r.Results, "FTP-005"); f == nil {
		t.Fatal("expected FTP-005 for weak username")
	}
}

func TestStrongUsername(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", []string{"FTP_USER=deploy_svc"}, nil)))
	if f := findRule(r.Results, "FTP-005"); f != nil {
		t.Fatal("should not flag non-default username")
	}
}

func TestPassivePortRange(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", []string{"PASV_MIN_PORT=30000", "PASV_MAX_PORT=31000"}, nil)))
	if f := findRule(r.Results, "FTP-006"); f == nil {
		t.Fatal("expected FTP-006 for passive port range")
	}
}

func TestNonFTPIgnored(t *testing.T) {
	r := Analyze(collected(svc("web", "nginx:latest", []string{"ANONYMOUS_ENABLE=true"}, nil)))
	if r.Summary.TotalFindings != 0 {
		t.Fatal("should ignore non-FTP service")
	}
}

func TestIsFTPService(t *testing.T) {
	cases := []struct {
		image string
		want  bool
	}{
		{"vsftpd", true},
		{"proftpd/server", true},
		{"pure-ftpd:latest", true},
		{"filezilla-server", true},
		{"nginx:latest", false},
	}
	for _, c := range cases {
		got := isFTPService(compose.Service{Image: c.image})
		if got != c.want {
			t.Errorf("isFTPService(%q) = %v, want %v", c.image, got, c.want)
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	r := Analyze(collected(
		svc("ftp1", "vsftpd", []string{"ANONYMOUS_ENABLE=true", "SSL_ENABLE=false"}, nil),
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
	if !strings.Contains(text, "FTP Server Security Audit") {
		t.Error("missing header")
	}
}

func TestFormatJSONValid(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", []string{"ANONYMOUS_ENABLE=true"}, nil)))
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

func TestAllFindings(t *testing.T) {
	r := Analyze(collected(svc("ftp", "vsftpd", []string{
		"ANONYMOUS_ENABLE=true",
		"SSL_ENABLE=false",
		"WRITE_ENABLE=yes",
		"FTP_USER=admin",
		"PASV_MIN_PORT=30000",
		"PASV_MAX_PORT=31000",
	}, []compose.PortMapping{port("21:21", 21)})))
	if r.Summary.TotalFindings != 6 {
		t.Errorf("expected 6 findings, got %d", r.Summary.TotalFindings)
	}
}
