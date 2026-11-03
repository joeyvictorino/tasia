package rabbitmqaudit

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

func TestDefaultCredentials(t *testing.T) {
	svc := compose.Service{
		Name:        "rabbitmq",
		Image:       "rabbitmq:3-management",
		Environment: []string{},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "default_creds" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected default_creds finding")
	}
}

func TestGuestGuest(t *testing.T) {
	svc := compose.Service{
		Name:  "rabbitmq",
		Image: "rabbitmq:3-management",
		Environment: []string{
			"RABBITMQ_DEFAULT_USER=guest",
			"RABBITMQ_DEFAULT_PASS=guest",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "default_creds" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected default_creds for guest/guest")
	}
}

func TestSecureCredentials(t *testing.T) {
	svc := compose.Service{
		Name:  "rabbitmq",
		Image: "rabbitmq:3-management",
		Environment: []string{
			"RABBITMQ_DEFAULT_USER=myapp",
			"RABBITMQ_DEFAULT_PASS=xK9m2pQ7vR4nL8wZ",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "default_creds" {
				t.Error("should not flag secure credentials")
			}
		}
	}
}

func TestExposedMgmtPort(t *testing.T) {
	svc := compose.Service{
		Name:  "rabbitmq",
		Image: "rabbitmq:3-management",
		Ports: []compose.PortMapping{
			{HostPort: 15672, TargetPort: 15672, Raw: "15672:15672"},
		},
		Environment: []string{
			"RABBITMQ_DEFAULT_USER=myapp",
			"RABBITMQ_DEFAULT_PASS=xK9m2pQ7vR4nL8wZ",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_mgmt" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected exposed_mgmt finding")
	}
}

func TestMgmtPortLocalhost(t *testing.T) {
	svc := compose.Service{
		Name:  "rabbitmq",
		Image: "rabbitmq:3-management",
		Ports: []compose.PortMapping{
			{HostPort: 15672, TargetPort: 15672, Raw: "127.0.0.1:15672:15672", HostIP: "127.0.0.1"},
		},
		Environment: []string{
			"RABBITMQ_DEFAULT_USER=myapp",
			"RABBITMQ_DEFAULT_PASS=xK9m2pQ7vR4nL8wZ",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_mgmt" {
				t.Error("should not flag management port bound to localhost")
			}
		}
	}
}

func TestUnencryptedAMQP(t *testing.T) {
	svc := compose.Service{
		Name:  "rabbitmq",
		Image: "rabbitmq:3",
		Ports: []compose.PortMapping{
			{HostPort: 5672, TargetPort: 5672, Raw: "5672:5672"},
		},
		Environment: []string{
			"RABBITMQ_DEFAULT_USER=myapp",
			"RABBITMQ_DEFAULT_PASS=xK9m2pQ7vR4nL8wZ",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unencrypted_amqp" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected unencrypted_amqp finding")
	}
}

func TestMissingUserOverride(t *testing.T) {
	svc := compose.Service{
		Name:        "rabbitmq",
		Image:       "rabbitmq:3",
		Environment: []string{},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_user_override" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_user_override finding")
	}
}

func TestExposedCookie(t *testing.T) {
	svc := compose.Service{
		Name:  "rabbitmq",
		Image: "rabbitmq:3",
		Environment: []string{
			"RABBITMQ_DEFAULT_USER=myapp",
			"RABBITMQ_DEFAULT_PASS=xK9m2pQ7vR4nL8wZ",
			"RABBITMQ_ERLANG_COOKIE=mysecretcookie",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_cookie" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected exposed_cookie finding")
	}
}

func TestMissingSSL(t *testing.T) {
	svc := compose.Service{
		Name:  "rabbitmq",
		Image: "rabbitmq:3",
		Environment: []string{
			"RABBITMQ_DEFAULT_USER=myapp",
			"RABBITMQ_DEFAULT_PASS=xK9m2pQ7vR4nL8wZ",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_ssl" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_ssl finding")
	}
}

func TestWithSSL(t *testing.T) {
	svc := compose.Service{
		Name:  "rabbitmq",
		Image: "rabbitmq:3",
		Environment: []string{
			"RABBITMQ_DEFAULT_USER=myapp",
			"RABBITMQ_DEFAULT_PASS=xK9m2pQ7vR4nL8wZ",
			"RABBITMQ_SSL_CERTFILE=/certs/cert.pem",
			"RABBITMQ_SSL_KEYFILE=/certs/key.pem",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_ssl" {
				t.Error("should not flag missing_ssl when SSL configured")
			}
		}
	}
}

func TestNonRabbitmqService(t *testing.T) {
	svc := compose.Service{
		Name:  "nginx",
		Image: "nginx:latest",
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 {
			t.Error("non-rabbitmq service should have no findings")
		}
	}
}

func TestIsRabbitmqImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"rabbitmq:3-management", true},
		{"bitnami/rabbitmq:3.12", true},
		{"rabbitmq:3", true},
		{"nginx:latest", false},
		{"redis:7", false},
	}
	for _, tt := range tests {
		if got := isRabbitmqImage(tt.image); got != tt.want {
			t.Errorf("isRabbitmqImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	svc := compose.Service{
		Name:  "rabbitmq",
		Image: "rabbitmq:3-management",
		Ports: []compose.PortMapping{
			{HostPort: 15672, TargetPort: 15672, Raw: "15672:15672"},
		},
		Environment: []string{},
	}
	r := Analyze(makeCollected(svc))
	if r.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.DefaultCreds != 1 {
		t.Errorf("expected 1 default_creds, got %d", r.Summary.DefaultCreds)
	}
	if r.Summary.ExposedMgmt != 1 {
		t.Errorf("expected 1 exposed_mgmt, got %d", r.Summary.ExposedMgmt)
	}
}

func TestFormatText(t *testing.T) {
	svc := compose.Service{
		Name:        "rabbitmq",
		Image:       "rabbitmq:3",
		Environment: []string{},
	}
	r := Analyze(makeCollected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "RabbitMQ Security Audit") {
		t.Error("expected header in output")
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/my/project"}
	r := Analyze(c)
	if r.Path != "/my/project" {
		t.Errorf("expected path /my/project, got %s", r.Path)
	}
}
