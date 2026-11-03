package graceful

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

func TestHardKillSignal(t *testing.T) {
	c := collected(compose.Service{Name: "db", Image: "postgres:15", StopSignal: "SIGKILL"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "graceful_hard_kill" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected graceful_hard_kill for SIGKILL stop signal")
	}
}

func TestNoSignalStateful(t *testing.T) {
	c := collected(compose.Service{Name: "db", Image: "postgres:15"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "graceful_no_signal" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected graceful_no_signal for stateful service without stop_signal")
	}
}

func TestNoSignalNonStateful(t *testing.T) {
	c := collected(compose.Service{Name: "web", Image: "nginx:1.25"})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "graceful_no_signal" {
				t.Error("non-stateful service should not be flagged for missing stop_signal")
			}
		}
	}
}

func TestShortGracePeriod(t *testing.T) {
	c := collected(compose.Service{Name: "db", Image: "postgres:15", StopGracePeriod: "2s"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "graceful_short_period" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected graceful_short_period for 2s grace on stateful service")
	}
}

func TestLongGracePeriod(t *testing.T) {
	c := collected(compose.Service{Name: "web", Image: "nginx:1.25", StopGracePeriod: "10m"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "graceful_long_period" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected graceful_long_period for 10m grace period")
	}
}

func TestNormalGracePeriod(t *testing.T) {
	c := collected(compose.Service{Name: "db", Image: "postgres:15", StopGracePeriod: "30s"})
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "graceful_short_period" || f.Rule == "graceful_long_period" {
				t.Errorf("30s grace should not trigger %s", f.Rule)
			}
		}
	}
}

func TestKillSignalNumeric(t *testing.T) {
	c := collected(compose.Service{Name: "app", Image: "myapp:1.0", StopSignal: "9"})
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "graceful_hard_kill" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected graceful_hard_kill for signal 9")
	}
}

func TestSummary(t *testing.T) {
	c := collected(
		compose.Service{Name: "db", Image: "postgres:15", StopSignal: "SIGKILL"},
		compose.Service{Name: "cache", Image: "redis:7", StopGracePeriod: "1s"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("total services = %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings < 2 {
		t.Error("expected at least 2 findings")
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{Name: "db", Image: "postgres:15", StopSignal: "SIGKILL"})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("empty text output")
	}
}

func TestJSON(t *testing.T) {
	c := collected(compose.Service{Name: "db", Image: "postgres:15"})
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestParseGracePeriod(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantOK  bool
	}{
		{"10s", 10, true},
		{"2m", 120, true},
		{"30", 30, true},
		{"", 0, false},
		{"abc", 0, false},
	}
	for _, tt := range tests {
		got, ok := parseGracePeriodSeconds(tt.input)
		if ok != tt.wantOK || got != tt.want {
			t.Errorf("parseGracePeriodSeconds(%q) = (%d, %v), want (%d, %v)",
				tt.input, got, ok, tt.want, tt.wantOK)
		}
	}
}
