package logging

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services []compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestNoLoggingConfig(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web"},
	})
	r := Analyze(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	if r.Services[0].Driver != "default" {
		t.Errorf("expected default driver, got %s", r.Services[0].Driver)
	}
	if r.Services[0].Score >= 80 {
		t.Errorf("expected score < 80, got %d", r.Services[0].Score)
	}
	hasRotationFinding := false
	for _, f := range r.Services[0].Findings {
		if f.Message == "No log rotation limits configured; logs may grow unbounded" {
			hasRotationFinding = true
		}
	}
	if !hasRotationFinding {
		t.Error("expected rotation finding")
	}
}

func TestNoneDriver(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Logging: &compose.LoggingConfig{Driver: "none", Options: map[string]string{}}},
	})
	r := Analyze(c)
	if r.Services[0].Score > 70 {
		t.Errorf("expected score <= 70 for none driver, got %d", r.Services[0].Score)
	}
	hasDisabledFinding := false
	for _, f := range r.Services[0].Findings {
		if f.Level == "high" {
			hasDisabledFinding = true
		}
	}
	if !hasDisabledFinding {
		t.Error("expected high-level finding for disabled logging")
	}
}

func TestGoodLogging(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Logging: &compose.LoggingConfig{
			Driver: "json-file",
			Options: map[string]string{
				"max-size": "10m",
				"max-file": "3",
			},
		}},
	})
	r := Analyze(c)
	if r.Services[0].Score < 90 {
		t.Errorf("expected score >= 90, got %d", r.Services[0].Score)
	}
	if r.Services[0].Grade != "A" {
		t.Errorf("expected grade A, got %s", r.Services[0].Grade)
	}
}

func TestMissingMaxSize(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Logging: &compose.LoggingConfig{
			Driver:  "json-file",
			Options: map[string]string{},
		}},
	})
	r := Analyze(c)
	hasSizeFinding := false
	for _, f := range r.Services[0].Findings {
		if f.Message == "No max-size log rotation limit configured" {
			hasSizeFinding = true
		}
	}
	if !hasSizeFinding {
		t.Error("expected max-size finding")
	}
}

func TestLargeMaxSize(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Logging: &compose.LoggingConfig{
			Driver: "json-file",
			Options: map[string]string{
				"max-size": "500m",
				"max-file": "5",
			},
		}},
	})
	r := Analyze(c)
	hasLargeFinding := false
	for _, f := range r.Services[0].Findings {
		if f.Level == "low" && f.Message != "" {
			hasLargeFinding = true
		}
	}
	if !hasLargeFinding {
		t.Error("expected finding for large max-size")
	}
}

func TestSyslogNoTLS(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Logging: &compose.LoggingConfig{
			Driver: "syslog",
			Options: map[string]string{
				"syslog-address": "tcp://logserver:514",
			},
		}},
	})
	r := Analyze(c)
	hasTLSFinding := false
	for _, f := range r.Services[0].Findings {
		if f.Level == "medium" {
			hasTLSFinding = true
		}
	}
	if !hasTLSFinding {
		t.Error("expected medium finding for syslog without TLS")
	}
}

func TestSyslogWithTLS(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Logging: &compose.LoggingConfig{
			Driver: "syslog",
			Options: map[string]string{
				"syslog-address": "tcp+tls://logserver:6514",
				"max-size":       "10m",
				"max-file":       "3",
			},
		}},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Level == "medium" && f.Message != "No max-size log rotation limit configured" {
			t.Errorf("unexpected medium finding: %s", f.Message)
		}
	}
}

func TestVolumeLogMount(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web",
			Volumes: []string{"/host/logs:/var/log/app"},
			Logging: &compose.LoggingConfig{
				Driver: "json-file",
				Options: map[string]string{
					"max-size": "10m",
					"max-file": "3",
				},
			},
		},
	})
	r := Analyze(c)
	hasVolFinding := false
	for _, f := range r.Services[0].Findings {
		if f.Level == "low" {
			hasVolFinding = true
		}
	}
	if !hasVolFinding {
		t.Error("expected finding for volume mount to /var/log")
	}
}

func TestSummary(t *testing.T) {
	c := makeCollected([]compose.Service{
		{Name: "web", Logging: &compose.LoggingConfig{
			Driver: "json-file",
			Options: map[string]string{
				"max-size": "10m",
				"max-file": "3",
			},
		}},
		{Name: "db"},
	})
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithLogDriver != 1 {
		t.Errorf("expected 1 with driver, got %d", r.Summary.WithLogDriver)
	}
}

func TestSizeBytes(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"10m", 10 * 1024 * 1024},
		{"1g", 1024 * 1024 * 1024},
		{"512k", 512 * 1024},
		{"100", 100},
	}
	for _, tt := range tests {
		got := sizeBytes(tt.input)
		if got != tt.expected {
			t.Errorf("sizeBytes(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestFormatText(t *testing.T) {
	c := makeCollected([]compose.Service{{Name: "web"}})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text")
	}
}
