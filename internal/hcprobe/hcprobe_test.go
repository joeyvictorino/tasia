package hcprobe

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeServiceMissingHealthcheck(t *testing.T) {
	svc := compose.Service{Name: "web", Image: "nginx"}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "missing_healthcheck" {
			found = true
		}
	}
	if !found {
		t.Error("expected missing_healthcheck finding")
	}
}

func TestAnalyzeServiceDisabledHealthcheck(t *testing.T) {
	svc := compose.Service{
		Name:  "web",
		Image: "nginx",
		Healthcheck: &compose.Healthcheck{Disable: true},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "disabled_healthcheck" {
			found = true
		}
	}
	if !found {
		t.Error("expected disabled_healthcheck finding")
	}
}

func TestAnalyzeServiceLongInterval(t *testing.T) {
	svc := compose.Service{
		Name:  "web",
		Image: "nginx",
		Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "curl", "localhost"},
			Interval: "5m",
			Retries:  3,
			Timeout:  "10s",
		},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "long_interval" {
			found = true
		}
	}
	if !found {
		t.Error("expected long_interval finding")
	}
}

func TestAnalyzeServiceNoRetries(t *testing.T) {
	svc := compose.Service{
		Name:  "web",
		Image: "nginx",
		Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "curl", "localhost"},
			Interval: "10s",
			Timeout:  "5s",
		},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "no_retries" {
			found = true
		}
	}
	if !found {
		t.Error("expected no_retries finding")
	}
}

func TestAnalyzeServiceShortTimeout(t *testing.T) {
	svc := compose.Service{
		Name:  "web",
		Image: "nginx",
		Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "curl", "localhost"},
			Interval: "10s",
			Retries:  3,
			Timeout:  "1s",
		},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	found := false
	for _, f := range sr.Findings {
		if f.Rule == "short_timeout" {
			found = true
		}
	}
	if !found {
		t.Error("expected short_timeout finding")
	}
}

func TestAnalyzeServiceHealthy(t *testing.T) {
	svc := compose.Service{
		Name:  "web",
		Image: "nginx",
		Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "curl", "localhost"},
			Interval: "30s",
			Retries:  3,
			Timeout:  "5s",
		},
	}
	sr := analyzeService(svc, "docker-compose.yml")
	if len(sr.Findings) != 0 {
		t.Errorf("expected no findings for healthy config, got %d", len(sr.Findings))
	}
}

func TestIsLongInterval(t *testing.T) {
	if !isLongInterval("5m") {
		t.Error("5m should be long")
	}
	if !isLongInterval("120s") {
		t.Error("120s should be long")
	}
	if isLongInterval("30s") {
		t.Error("30s should not be long")
	}
	if isLongInterval("") {
		t.Error("empty should not be long")
	}
}

func TestIsShortTimeout(t *testing.T) {
	if !isShortTimeout("1s") {
		t.Error("1s should be short")
	}
	if !isShortTimeout("2s") {
		t.Error("2s should be short")
	}
	if isShortTimeout("5s") {
		t.Error("5s should not be short")
	}
	if isShortTimeout("") {
		t.Error("empty should not be short")
	}
}

func TestAnalyze(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "web", Image: "nginx"},
					{Name: "api", Image: "myapp", Healthcheck: &compose.Healthcheck{
						Test: []string{"CMD", "curl", "localhost"}, Interval: "30s", Retries: 3, Timeout: "5s",
					}},
				},
			},
		},
	}
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.MissingProbe != 1 {
		t.Errorf("expected 1 missing probe, got %d", r.Summary.MissingProbe)
	}
}

func TestFormatText(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{
				Path:     "docker-compose.yml",
				Services: []compose.Service{{Name: "svc1", Image: "nginx"}},
			},
		},
	}
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Healthcheck Probe") {
		t.Error("expected header in text output")
	}
}

func TestSummarize(t *testing.T) {
	services := []ServiceResult{
		{Service: "a", Findings: []Finding{
			{Rule: "missing_healthcheck"},
		}},
		{Service: "b", Findings: []Finding{
			{Rule: "long_interval"},
			{Rule: "no_retries"},
		}},
	}
	s := summarize(services)
	if s.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", s.TotalFindings)
	}
	if s.MissingProbe != 1 {
		t.Errorf("expected 1 missing probe, got %d", s.MissingProbe)
	}
}
