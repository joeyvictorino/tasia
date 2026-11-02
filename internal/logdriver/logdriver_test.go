package logdriver

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

func TestNoLoggingConfig(t *testing.T) {
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	if len(r.Services[0].Findings) == 0 {
		t.Fatal("expected findings for missing logging config")
	}
	if r.Services[0].Findings[0].Rule != "log_driver_missing" {
		t.Errorf("expected log_driver_missing, got %s", r.Services[0].Findings[0].Rule)
	}
}

func TestDriverNone(t *testing.T) {
	c := collected(compose.Service{
		Name:    "agent",
		Logging: &compose.LoggingConfig{Driver: "none"},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) == 0 {
		t.Fatal("expected findings for driver: none")
	}
	if r.Services[0].Findings[0].Rule != "log_driver_stealth" {
		t.Errorf("expected log_driver_stealth, got %s", r.Services[0].Findings[0].Rule)
	}
	if r.Services[0].Findings[0].Level != "high" {
		t.Errorf("expected high severity for stealth driver")
	}
}

func TestJsonFileNoRotation(t *testing.T) {
	c := collected(compose.Service{
		Name:    "api",
		Logging: &compose.LoggingConfig{Driver: "json-file"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "log_driver_no_rotation" {
			found = true
		}
	}
	if !found {
		t.Error("expected log_driver_no_rotation finding for json-file without limits")
	}
}

func TestJsonFileWithRotation(t *testing.T) {
	c := collected(compose.Service{
		Name: "api",
		Logging: &compose.LoggingConfig{
			Driver:  "json-file",
			Options: map[string]string{"max-size": "10m", "max-file": "3"},
		},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for properly configured json-file, got %d", len(r.Services[0].Findings))
	}
}

func TestJsonFileNoMaxSizeOnly(t *testing.T) {
	c := collected(compose.Service{
		Name: "api",
		Logging: &compose.LoggingConfig{
			Driver:  "json-file",
			Options: map[string]string{"max-file": "3"},
		},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "log_driver_no_max_size" {
			found = true
		}
	}
	if !found {
		t.Error("expected log_driver_no_max_size for json-file with max-file but no max-size")
	}
}

func TestSyslogUnencrypted(t *testing.T) {
	c := collected(compose.Service{
		Name: "api",
		Logging: &compose.LoggingConfig{
			Driver:  "syslog",
			Options: map[string]string{"syslog-address": "udp://logs.example.com:514"},
		},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "log_driver_syslog_unencrypted" {
			found = true
		}
	}
	if !found {
		t.Error("expected syslog unencrypted finding")
	}
}

func TestSyslogEncrypted(t *testing.T) {
	c := collected(compose.Service{
		Name: "api",
		Logging: &compose.LoggingConfig{
			Driver:  "syslog",
			Options: map[string]string{"syslog-address": "tcp+tls://logs.example.com:6514"},
		},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for encrypted syslog, got %d", len(r.Services[0].Findings))
	}
}

func TestFluentdNoTag(t *testing.T) {
	c := collected(compose.Service{
		Name:    "api",
		Logging: &compose.LoggingConfig{Driver: "fluentd"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "log_driver_no_tag" {
			found = true
		}
	}
	if !found {
		t.Error("expected log_driver_no_tag for fluentd without tag")
	}
}

func TestFluentdWithTag(t *testing.T) {
	c := collected(compose.Service{
		Name: "api",
		Logging: &compose.LoggingConfig{
			Driver:  "fluentd",
			Options: map[string]string{"tag": "myapp.{{.Name}}"},
		},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for fluentd with tag, got %d", len(r.Services[0].Findings))
	}
}

func TestEmptyServices(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleServices(t *testing.T) {
	c := collected(
		compose.Service{Name: "web", Logging: &compose.LoggingConfig{Driver: "none"}},
		compose.Service{Name: "api"},
		compose.Service{Name: "db", Logging: &compose.LoggingConfig{
			Driver:  "json-file",
			Options: map[string]string{"max-size": "10m", "max-file": "3"},
		}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.StealthDrivers != 1 {
		t.Errorf("expected 1 stealth driver, got %d", r.Summary.StealthDrivers)
	}
	if r.Summary.MissingConfig != 1 {
		t.Errorf("expected 1 missing config, got %d", r.Summary.MissingConfig)
	}
}

func TestSummaryTotalFindings(t *testing.T) {
	c := collected(
		compose.Service{Name: "a", Logging: &compose.LoggingConfig{Driver: "none"}},
		compose.Service{Name: "b"},
	)
	r := Analyze(c)
	if r.Summary.TotalFindings != 2 {
		t.Errorf("expected 2 total findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{Name: "web", Logging: &compose.LoggingConfig{Driver: "none"}})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !containsStr(text, "Log Driver Audit") {
		t.Error("expected header in text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "web", Logging: &compose.LoggingConfig{Driver: "none"}})
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

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstr(s, sub))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
