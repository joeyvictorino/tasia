package logforward

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func findRule(results []ServiceResult, rule string) bool {
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return true
			}
		}
	}
	return false
}

func TestNoLoggingConfig(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if !findRule(r.Services, "logforward_no_config") {
		t.Error("expected logforward_no_config finding for service without logging")
	}
}

func TestWithLoggingConfig(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Logging: &compose.LoggingConfig{Driver: "json-file", Options: map[string]string{}},
	})
	r := Analyze(c)
	if findRule(r.Services, "logforward_no_config") {
		t.Error("should not flag service with logging config")
	}
}

func TestSyslogNoAddress(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Logging: &compose.LoggingConfig{Driver: "syslog", Options: map[string]string{}},
	})
	r := Analyze(c)
	if !findRule(r.Services, "logforward_insecure_syslog") {
		t.Error("expected insecure_syslog finding")
	}
}

func TestSyslogNoTLS(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "syslog",
			Options: map[string]string{"syslog-address": "tcp://loghost:514"},
		},
	})
	r := Analyze(c)
	if !findRule(r.Services, "logforward_no_tls") {
		t.Error("expected no_tls finding for syslog without TLS")
	}
}

func TestSyslogWithTLS(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "syslog",
			Options: map[string]string{"syslog-address": "tcp+tls://loghost:6514"},
		},
	})
	r := Analyze(c)
	if findRule(r.Services, "logforward_no_tls") {
		t.Error("should not flag syslog with TLS")
	}
	if findRule(r.Services, "logforward_insecure_syslog") {
		t.Error("should not flag syslog with address")
	}
}

func TestSplunkNoVerify(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "splunk",
			Options: map[string]string{"splunk-verify-connection": "false"},
		},
	})
	r := Analyze(c)
	if !findRule(r.Services, "logforward_splunk_no_ssl") {
		t.Error("expected splunk_no_ssl finding")
	}
}

func TestSplunkInsecureSkip(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "splunk",
			Options: map[string]string{"splunk-insecureskipverify": "true"},
		},
	})
	r := Analyze(c)
	if !findRule(r.Services, "logforward_splunk_no_ssl") {
		t.Error("expected splunk_no_ssl finding for insecureskipverify")
	}
}

func TestSplunkSecure(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "splunk",
			Options: map[string]string{"splunk-verify-connection": "true"},
		},
	})
	r := Analyze(c)
	if findRule(r.Services, "logforward_splunk_no_ssl") {
		t.Error("should not flag secure Splunk config")
	}
}

func TestFluentdInsecure(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "fluentd",
			Options: map[string]string{"fluentd-address": "tcp://fluentd:24224"},
		},
	})
	r := Analyze(c)
	if !findRule(r.Services, "logforward_fluentd_insecure") {
		t.Error("expected fluentd_insecure finding")
	}
}

func TestFluentdWithTLSOption(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "fluentd",
			Options: map[string]string{"fluentd-address": "tcp://fluentd:24224", "tls-enabled": "true"},
		},
	})
	r := Analyze(c)
	if findRule(r.Services, "logforward_fluentd_insecure") {
		t.Error("should not flag fluentd with TLS option")
	}
}

func TestGelfUDP(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "gelf",
			Options: map[string]string{"gelf-address": "udp://graylog:12201"},
		},
	})
	r := Analyze(c)
	if !findRule(r.Services, "logforward_no_tls") {
		t.Error("expected no_tls finding for GELF over UDP")
	}
}

func TestGelfTCP(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "gelf",
			Options: map[string]string{"gelf-address": "tcp://graylog:12201"},
		},
	})
	r := Analyze(c)
	if findRule(r.Services, "logforward_no_tls") {
		t.Error("should not flag GELF over TCP")
	}
}

func TestExposedToken(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "splunk",
			Options: map[string]string{"splunk-token": "abc123-hardcoded"},
		},
	})
	r := Analyze(c)
	if !findRule(r.Services, "logforward_exposed_token") {
		t.Error("expected exposed_token finding for hardcoded token")
	}
}

func TestTokenFromEnvVar(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "splunk",
			Options: map[string]string{"splunk-token": "${SPLUNK_TOKEN}"},
		},
	})
	r := Analyze(c)
	if findRule(r.Services, "logforward_exposed_token") {
		t.Error("should not flag token from env var reference")
	}
}

func TestMultipleServices(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "web", Logging: &compose.LoggingConfig{Driver: "json-file", Options: map[string]string{}}},
		compose.Service{Name: "worker"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a", Logging: &compose.LoggingConfig{Driver: "syslog", Options: map[string]string{"syslog-address": "tcp://log:514"}}},
		compose.Service{Name: "b"},
	)
	r := Analyze(c)
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Logging: &compose.LoggingConfig{Driver: "syslog", Options: map[string]string{}}})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Log Forwarding") {
		t.Error("expected 'Log Forwarding' in output")
	}
	if !strings.Contains(text, "web") {
		t.Error("expected service name in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Logging: &compose.LoggingConfig{Driver: "json-file", Options: map[string]string{}},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "no findings") {
		t.Error("expected 'no findings' in output")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestReportPath(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.Path)
	}
}

func TestCaseInsensitiveDriver(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "SYSLOG",
			Options: map[string]string{},
		},
	})
	r := Analyze(c)
	if !findRule(r.Services, "logforward_insecure_syslog") {
		t.Error("expected case-insensitive driver detection")
	}
}

func TestTokenAPIKey(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
		Logging: &compose.LoggingConfig{
			Driver:  "fluentd",
			Options: map[string]string{"fluentd-address": "tcp://f:24224", "api-key": "hardcoded123"},
		},
	})
	r := Analyze(c)
	if !findRule(r.Services, "logforward_exposed_token") {
		t.Error("expected exposed_token finding for api-key")
	}
}
