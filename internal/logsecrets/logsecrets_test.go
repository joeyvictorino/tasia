package logsecrets

import (
	"encoding/json"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func hasRule(sr ServiceResult, rule string) bool {
	for _, f := range sr.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestSplunkTokenDetected(t *testing.T) {
	c := collected(compose.Service{
		Name: "app",
		Logging: &compose.LoggingConfig{
			Driver:  "splunk",
			Options: map[string]string{"splunk-token": "abc123secret"},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "log_secret_in_option") {
		t.Error("expected log_secret_in_option for splunk-token")
	}
}

func TestPasswordInOptionValue(t *testing.T) {
	c := collected(compose.Service{
		Name: "worker",
		Logging: &compose.LoggingConfig{
			Driver:  "syslog",
			Options: map[string]string{"syslog-address": "password=s3cret"},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "log_secret_in_option") {
		t.Error("expected log_secret_in_option for password pattern")
	}
}

func TestCredentialInURL(t *testing.T) {
	c := collected(compose.Service{
		Name: "api",
		Logging: &compose.LoggingConfig{
			Driver:  "fluentd",
			Options: map[string]string{"fluentd-address": "http://user:pass@loghost:24224"},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "log_secret_in_url") {
		t.Error("expected log_secret_in_url for credentials in URL")
	}
}

func TestTokenInQueryString(t *testing.T) {
	c := collected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "gelf",
			Options: map[string]string{"gelf-address": "http://logs.example.com?token=abc123"},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "log_secret_in_url") {
		t.Error("expected log_secret_in_url for token in query string")
	}
}

func TestInsecureHTTPTransport(t *testing.T) {
	c := collected(compose.Service{
		Name: "svc",
		Logging: &compose.LoggingConfig{
			Driver:  "gelf",
			Options: map[string]string{"gelf-address": "http://loghost:12201"},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "log_insecure_transport") {
		t.Error("expected log_insecure_transport for http:// address")
	}
}

func TestInsecureTCPTransport(t *testing.T) {
	c := collected(compose.Service{
		Name: "svc",
		Logging: &compose.LoggingConfig{
			Driver:  "syslog",
			Options: map[string]string{"syslog-address": "tcp://loghost:514"},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "log_insecure_transport") {
		t.Error("expected log_insecure_transport for tcp:// address")
	}
}

func TestSecureHTTPSTransportClean(t *testing.T) {
	c := collected(compose.Service{
		Name: "svc",
		Logging: &compose.LoggingConfig{
			Driver:  "gelf",
			Options: map[string]string{"gelf-address": "https://loghost:12201"},
		},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "log_insecure_transport") {
		t.Error("should not flag https:// as insecure")
	}
}

func TestNoLoggingConfigClean(t *testing.T) {
	c := collected(compose.Service{Name: "clean"})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for service with no logging config, got %d", len(r.Services[0].Findings))
	}
}

func TestSafeOptionsClean(t *testing.T) {
	c := collected(compose.Service{
		Name: "app",
		Logging: &compose.LoggingConfig{
			Driver:  "json-file",
			Options: map[string]string{"max-size": "10m", "max-file": "3"},
		},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for safe logging options, got %d", len(r.Services[0].Findings))
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestSummaryCountsCorrect(t *testing.T) {
	c := collected(
		compose.Service{
			Name: "a",
			Logging: &compose.LoggingConfig{
				Driver:  "splunk",
				Options: map[string]string{"splunk-token": "secret123"},
			},
		},
		compose.Service{
			Name: "b",
			Logging: &compose.LoggingConfig{
				Driver:  "gelf",
				Options: map[string]string{"gelf-address": "http://host:12201"},
			},
		},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.SecretsInOptions < 1 {
		t.Error("expected at least 1 secret in options")
	}
	if r.Summary.InsecureTransport < 1 {
		t.Error("expected at least 1 insecure transport")
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "splunk",
			Options: map[string]string{"splunk-token": "abc"},
		},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !containsStr(text, "Log Secret") {
		t.Error("expected header in text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "splunk",
			Options: map[string]string{"splunk-token": "abc"},
		},
	})
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Report
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service after round-trip, got %d", r2.Summary.TotalServices)
	}
}

func TestAWSCredentialPattern(t *testing.T) {
	c := collected(compose.Service{
		Name: "etl",
		Logging: &compose.LoggingConfig{
			Driver:  "awslogs",
			Options: map[string]string{"awslogs-credentials-endpoint": "http://169.254.170.2/creds"},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "log_secret_in_option") {
		t.Error("expected log_secret_in_option for awslogs-credentials-endpoint")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
