package elasticaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.ComposeFile{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestSecurityDisabled(t *testing.T) {
	svc := compose.Service{
		Name:        "es",
		Image:       "elasticsearch:8.10",
		Environment: []string{"xpack.security.enabled=false"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "security_disabled" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected security_disabled finding")
	}
}

func TestSecurityDisabledUpperCase(t *testing.T) {
	svc := compose.Service{
		Name:        "es",
		Image:       "elasticsearch:8.10",
		Environment: []string{"XPACK_SECURITY_ENABLED=false"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "security_disabled" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected security_disabled finding with uppercase env var")
	}
}

func TestSecurityEnabled(t *testing.T) {
	svc := compose.Service{
		Name:  "es",
		Image: "elasticsearch:8.10",
		Environment: []string{
			"xpack.security.enabled=true",
			"xpack.security.transport.ssl.enabled=true",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "security_disabled" {
				t.Error("should not flag security_disabled when enabled=true")
			}
		}
	}
}

func TestExposedHTTPPort(t *testing.T) {
	svc := compose.Service{
		Name:  "es",
		Image: "elasticsearch:8.10",
		Ports: []compose.PortMapping{
			{HostPort: 9200, TargetPort: 9200, Raw: "9200:9200"},
		},
		Environment: []string{"xpack.security.transport.ssl.enabled=true"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_port" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected exposed_port finding")
	}
}

func TestExposedTransportPort(t *testing.T) {
	svc := compose.Service{
		Name:  "es",
		Image: "elasticsearch:8.10",
		Ports: []compose.PortMapping{
			{HostPort: 9300, TargetPort: 9300, Raw: "9300:9300"},
		},
		Environment: []string{"xpack.security.transport.ssl.enabled=true"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_port" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected exposed_port finding for transport port")
	}
}

func TestLocalhostPortNotFlagged(t *testing.T) {
	svc := compose.Service{
		Name:  "es",
		Image: "elasticsearch:8.10",
		Ports: []compose.PortMapping{
			{HostPort: 9200, TargetPort: 9200, Raw: "127.0.0.1:9200:9200", HostIP: "127.0.0.1"},
		},
		Environment: []string{"xpack.security.transport.ssl.enabled=true"},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_port" {
				t.Error("should not flag port bound to localhost")
			}
		}
	}
}

func TestDefaultCredentials(t *testing.T) {
	svc := compose.Service{
		Name:        "es",
		Image:       "elasticsearch:8.10",
		Environment: []string{"ELASTIC_PASSWORD=changeme", "xpack.security.transport.ssl.enabled=true"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "default_credentials" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected default_credentials finding")
	}
}

func TestStrongPassword(t *testing.T) {
	svc := compose.Service{
		Name:  "es",
		Image: "elasticsearch:8.10",
		Environment: []string{
			"ELASTIC_PASSWORD=s3cur3P@ssw0rd!",
			"xpack.security.transport.ssl.enabled=true",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "default_credentials" {
				t.Error("should not flag strong password")
			}
		}
	}
}

func TestMissingTLS(t *testing.T) {
	svc := compose.Service{
		Name:        "es",
		Image:       "elasticsearch:8.10",
		Environment: []string{"ELASTIC_PASSWORD=s3cur3!"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_tls" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_tls finding")
	}
}

func TestWithTLS(t *testing.T) {
	svc := compose.Service{
		Name:  "es",
		Image: "elasticsearch:8.10",
		Environment: []string{
			"xpack.security.transport.ssl.enabled=true",
			"xpack.security.http.ssl.enabled=true",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_tls" {
				t.Error("should not flag when TLS is configured")
			}
		}
	}
}

func TestAnonymousAccessWithSecDisabled(t *testing.T) {
	svc := compose.Service{
		Name:        "es",
		Image:       "elasticsearch:8.10",
		Environment: []string{"xpack.security.enabled=false"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "anonymous_access" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected anonymous_access finding")
	}
}

func TestUnsafeConfigHostNetwork(t *testing.T) {
	svc := compose.Service{
		Name:        "es",
		Image:       "elasticsearch:8.10",
		NetworkMode: "host",
		Environment: []string{
			"discovery.type=single-node",
			"xpack.security.transport.ssl.enabled=true",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unsafe_config" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected unsafe_config for host network single-node")
	}
}

func TestWritableConfigMount(t *testing.T) {
	svc := compose.Service{
		Name:    "es",
		Image:   "elasticsearch:8.10",
		Volumes: []string{"./config:/etc/elasticsearch"},
		Environment: []string{
			"xpack.security.transport.ssl.enabled=true",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unsafe_config" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected unsafe_config for writable config mount")
	}
}

func TestNonElasticService(t *testing.T) {
	svc := compose.Service{
		Name:  "redis",
		Image: "redis:7",
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 {
			t.Error("non-elastic service should have no findings")
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	svc := compose.Service{
		Name:  "es",
		Image: "elasticsearch:8.10",
		Ports: []compose.PortMapping{
			{HostPort: 9200, TargetPort: 9200, Raw: "9200:9200"},
		},
		Environment: []string{"xpack.security.enabled=false"},
	}
	r := Analyze(makeCollected(svc))
	if r.Summary.SecurityDisabled != 1 {
		t.Errorf("expected 1 security disabled, got %d", r.Summary.SecurityDisabled)
	}
	if r.Summary.ExposedPorts != 1 {
		t.Errorf("expected 1 exposed port, got %d", r.Summary.ExposedPorts)
	}
	if r.Summary.AnonymousAccess != 1 {
		t.Errorf("expected 1 anonymous access, got %d", r.Summary.AnonymousAccess)
	}
}

func TestFormatTextOutput(t *testing.T) {
	svc := compose.Service{
		Name:        "es",
		Image:       "elasticsearch:8.10",
		Environment: []string{"xpack.security.enabled=false"},
	}
	r := Analyze(makeCollected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "Elasticsearch Security Audit") {
		t.Error("expected header in output")
	}
	if !strings.Contains(text, "security") {
		t.Error("expected security reference in output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/empty"})
	text := FormatText(r)
	if !strings.Contains(text, "0 services") {
		t.Error("expected zero services in empty report")
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/my/elastic"}
	r := Analyze(c)
	if r.Path != "/my/elastic" {
		t.Errorf("expected path /my/elastic, got %s", r.Path)
	}
}

func TestOpensearchDetection(t *testing.T) {
	svc := compose.Service{
		Name:        "opensearch",
		Image:       "opensearchproject/opensearch:2.11",
		Environment: []string{"DISABLE_SECURITY_PLUGIN=true"},
	}
	r := Analyze(makeCollected(svc))
	if r.Summary.TotalFindings == 0 {
		t.Error("expected findings for OpenSearch service")
	}
}

func TestIsElasticImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"elasticsearch:8.10", true},
		{"elastic/elasticsearch:8.10", true},
		{"bitnami/elasticsearch:8", true},
		{"opensearchproject/opensearch:2.11", true},
		{"postgres:14", false},
		{"nginx:latest", false},
	}
	for _, tt := range tests {
		if got := isElasticImage(tt.image); got != tt.want {
			t.Errorf("isElasticImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}
