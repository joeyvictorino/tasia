package healthz

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

func TestNoHealthcheck(t *testing.T) {
	c := collected(compose.Service{
		Name: "web",
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "healthz_no_check") {
		t.Error("expected healthz_no_check for service without healthcheck")
	}
	if r.Summary.NoCheck != 1 {
		t.Errorf("expected 1 no_check, got %d", r.Summary.NoCheck)
	}
}

func TestShellInjection(t *testing.T) {
	c := collected(compose.Service{
		Name: "app",
		Healthcheck: &compose.Healthcheck{
			Test:    []string{"CMD-SHELL", "curl http://localhost | grep ok"},
			Retries: 3,
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "healthz_shell_injection") {
		t.Error("expected healthz_shell_injection for pipe in healthcheck")
	}
	if r.Summary.ShellInjection != 1 {
		t.Errorf("expected 1 shell injection, got %d", r.Summary.ShellInjection)
	}
}

func TestDollarExpansion(t *testing.T) {
	c := collected(compose.Service{
		Name: "app",
		Healthcheck: &compose.Healthcheck{
			Test:    []string{"CMD-SHELL", "curl http://localhost:$(cat /tmp/port)"},
			Retries: 3,
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "healthz_shell_injection") {
		t.Error("expected healthz_shell_injection for $() in healthcheck")
	}
}

func TestShortInterval(t *testing.T) {
	c := collected(compose.Service{
		Name: "fast",
		Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "true"},
			Interval: "2s",
			Retries:  3,
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "healthz_short_interval") {
		t.Error("expected healthz_short_interval for 2s interval")
	}
	if r.Summary.ShortInterval != 1 {
		t.Errorf("expected 1 short interval, got %d", r.Summary.ShortInterval)
	}
}

func TestNormalIntervalSafe(t *testing.T) {
	c := collected(compose.Service{
		Name: "normal",
		Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "true"},
			Interval: "30s",
			Retries:  3,
		},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "healthz_short_interval") {
		t.Error("should not flag 30s interval as short")
	}
}

func TestNoRetries(t *testing.T) {
	c := collected(compose.Service{
		Name: "fragile",
		Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "true"},
			Interval: "10s",
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "healthz_no_retries") {
		t.Error("expected healthz_no_retries for 0 retries")
	}
	if r.Summary.NoRetries != 1 {
		t.Errorf("expected 1 no retries, got %d", r.Summary.NoRetries)
	}
}

func TestHealthyService(t *testing.T) {
	c := collected(compose.Service{
		Name: "healthy",
		Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "curl", "-f", "http://localhost/health"},
			Interval: "30s",
			Retries:  3,
		},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for healthy service, got %d", len(r.Services[0].Findings))
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{Name: "clean"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "healthz_no_check") {
		t.Error("expected healthz_no_check for clean service without healthcheck")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleViolations(t *testing.T) {
	c := collected(compose.Service{
		Name: "allbad",
		Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD-SHELL", "curl localhost | grep ok"},
			Interval: "1s",
		},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name: "app",
		Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD-SHELL", "curl localhost | grep ok"},
			Interval: "10s",
			Retries:  3,
		},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name: "web",
		Healthcheck: &compose.Healthcheck{
			Test:     []string{"CMD", "true"},
			Interval: "10s",
			Retries:  3,
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
