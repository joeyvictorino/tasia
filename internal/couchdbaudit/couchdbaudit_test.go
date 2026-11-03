package couchdbaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, env []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports}
}

func allIf(target int) compose.PortMapping {
	return compose.PortMapping{HostPort: target, TargetPort: target, HostIP: "0.0.0.0"}
}

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func colPath(path string, svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: path, ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func TestIsCouchDBImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"couchdb:3.3", true},
		{"bitnami/couchdb:latest", true},
		{"apache/couchdb:3", true},
		{"nginx:latest", false},
		{"COUCHDB:latest", true},
	}
	for _, tt := range tests {
		if got := isCouchDBImage(tt.image); got != tt.want {
			t.Errorf("isCouchDBImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestAdminParty(t *testing.T) {
	r := Analyze(col(svc("db", "couchdb:3", nil, nil)))
	if r.Summary.AdminParty == 0 {
		t.Error("expected couchdb_admin_party finding when no credentials set")
	}
}

func TestAdminPartyDisabled(t *testing.T) {
	r := Analyze(col(svc("db", "couchdb:3",
		[]string{"COUCHDB_USER=admin", "COUCHDB_PASSWORD=s3cur3P@ss!"}, nil)))
	if r.Summary.AdminParty != 0 {
		t.Error("expected no admin_party finding when credentials set")
	}
}

func TestDefaultPassword(t *testing.T) {
	r := Analyze(col(svc("db", "couchdb:3",
		[]string{"COUCHDB_USER=admin", "COUCHDB_PASSWORD=admin"}, nil)))
	if r.Summary.DefaultPassword == 0 {
		t.Error("expected couchdb_default_password finding for weak password")
	}
}

func TestStrongPassword(t *testing.T) {
	r := Analyze(col(svc("db", "couchdb:3",
		[]string{"COUCHDB_USER=admin", "COUCHDB_PASSWORD=s3cur3P@ss!"}, nil)))
	if r.Summary.DefaultPassword != 0 {
		t.Error("expected no default_password finding with strong password")
	}
}

func TestNoTLS(t *testing.T) {
	r := Analyze(col(svc("db", "couchdb:3", nil, nil)))
	if r.Summary.NoTLS == 0 {
		t.Error("expected couchdb_no_tls finding")
	}
}

func TestTLSEnabled(t *testing.T) {
	r := Analyze(col(svc("db", "couchdb:3",
		[]string{"COUCHDB_CERTFILE=/certs/cert.pem", "COUCHDB_USER=admin", "COUCHDB_PASSWORD=s3cur3!"}, nil)))
	if r.Summary.NoTLS != 0 {
		t.Error("expected no couchdb_no_tls finding when TLS enabled")
	}
}

func TestExposedHTTPPort(t *testing.T) {
	r := Analyze(col(svc("db", "couchdb:3", nil, []compose.PortMapping{allIf(5984)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected couchdb_exposed_port finding for 5984")
	}
}

func TestExposedEPMDPort(t *testing.T) {
	r := Analyze(col(svc("db", "couchdb:3", nil, []compose.PortMapping{allIf(4369)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected couchdb_exposed_port finding for 4369")
	}
}

func TestMultiplePortsExposed(t *testing.T) {
	r := Analyze(col(svc("db", "couchdb:3", nil,
		[]compose.PortMapping{allIf(5984), allIf(6984), allIf(4369)})))
	if r.Summary.ExposedPort != 3 {
		t.Errorf("expected 3 port findings, got %d", r.Summary.ExposedPort)
	}
}

func TestCORSOpen(t *testing.T) {
	r := Analyze(col(svc("db", "couchdb:3",
		[]string{"COUCHDB_USER=admin", "COUCHDB_PASSWORD=s3cur3!", "COUCHDB_CORS_ENABLE=true", "COUCHDB_CORS_ORIGINS=*"}, nil)))
	if r.Summary.CORSOpen == 0 {
		t.Error("expected couchdb_cors_open finding")
	}
}

func TestCORSNotOpenWithoutWildcard(t *testing.T) {
	r := Analyze(col(svc("db", "couchdb:3",
		[]string{"COUCHDB_USER=admin", "COUCHDB_PASSWORD=s3cur3!", "COUCHDB_CORS_ENABLE=true", "COUCHDB_CORS_ORIGINS=https://example.com"}, nil)))
	if r.Summary.CORSOpen != 0 {
		t.Error("expected no cors_open finding when origin is specific")
	}
}

func TestNonCouchDBSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("db", "couchdb:3", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "CouchDB Security Audit") {
		t.Error("missing title")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No CouchDB services found") {
		t.Error("expected empty message")
	}
}

func TestEmptyCollection(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	if len(r.Services) != 0 {
		t.Error("expected empty report")
	}
}

func TestReportPath(t *testing.T) {
	r := Analyze(colPath("/mydir"))
	if r.Path != "/mydir" {
		t.Errorf("expected /mydir, got %s", r.Path)
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(col(
		svc("db1", "couchdb:3", nil, nil),
		svc("db2", "bitnami/couchdb:latest", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}
