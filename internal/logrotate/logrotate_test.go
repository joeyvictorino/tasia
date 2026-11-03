package logrotate

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

func TestNoRotationPolicy(t *testing.T) {
	c := collected(compose.Service{
		Name: "app",
		Logging: &compose.LoggingConfig{
			Driver:  "json-file",
			Options: map[string]string{},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "logrotate_no_rotation") {
		t.Error("expected logrotate_no_rotation for driver without max-size/max-file")
	}
}

func TestRotationPolicyPresent(t *testing.T) {
	c := collected(compose.Service{
		Name: "app",
		Logging: &compose.LoggingConfig{
			Driver: "json-file",
			Options: map[string]string{
				"max-size": "10m",
				"max-file": "3",
			},
		},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "logrotate_no_rotation") {
		t.Error("should not flag driver with max-size and max-file")
	}
}

func TestMissingMaxFile(t *testing.T) {
	c := collected(compose.Service{
		Name: "app",
		Logging: &compose.LoggingConfig{
			Driver: "json-file",
			Options: map[string]string{
				"max-size": "10m",
			},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "logrotate_no_rotation") {
		t.Error("expected logrotate_no_rotation when max-file is missing")
	}
}

func TestDriverNoneNotFlagged(t *testing.T) {
	c := collected(compose.Service{
		Name: "app",
		Logging: &compose.LoggingConfig{
			Driver: "none",
		},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "logrotate_no_rotation") {
		t.Error("should not flag driver 'none'")
	}
}

func TestUnboundedLogVolume(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"./logs:/var/log"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "logrotate_unbounded_volume") {
		t.Error("expected logrotate_unbounded_volume for /var/log mount")
	}
}

func TestUnboundedLogVolumeAppLogs(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"logvol:/app/logs"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "logrotate_unbounded_volume") {
		t.Error("expected logrotate_unbounded_volume for /app/logs mount")
	}
}

func TestNormalVolumeNotFlagged(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"./data:/app/data"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "logrotate_unbounded_volume") {
		t.Error("should not flag /app/data volume as log volume")
	}
}

func TestStdoutNoDriver(t *testing.T) {
	c := collected(compose.Service{
		Name: "web",
		Ports: []compose.PortMapping{
			{HostPort: 8080, TargetPort: 8080},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "logrotate_stdout_no_driver") {
		t.Error("expected logrotate_stdout_no_driver for service with ports but no logging config")
	}
}

func TestStdoutWithDriverNotFlagged(t *testing.T) {
	c := collected(compose.Service{
		Name: "web",
		Ports: []compose.PortMapping{
			{HostPort: 8080, TargetPort: 8080},
		},
		Logging: &compose.LoggingConfig{
			Driver: "json-file",
			Options: map[string]string{
				"max-size": "10m",
				"max-file": "3",
			},
		},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "logrotate_stdout_no_driver") {
		t.Error("should not flag service with explicit logging driver")
	}
}

func TestNoPortsNoStdoutWarning(t *testing.T) {
	c := collected(compose.Service{
		Name:  "worker",
		Image: "worker:latest",
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "logrotate_stdout_no_driver") {
		t.Error("should not flag service with no ports")
	}
}

func TestSummaryTotals(t *testing.T) {
	c := collected(
		compose.Service{
			Name: "a",
			Logging: &compose.LoggingConfig{
				Driver:  "syslog",
				Options: map[string]string{},
			},
		},
		compose.Service{
			Name:    "b",
			Volumes: []string{"v:/var/log"},
		},
	)
	r := Analyze(c)
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name: "app",
		Logging: &compose.LoggingConfig{
			Driver:  "json-file",
			Options: map[string]string{},
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
		Name: "app",
		Logging: &compose.LoggingConfig{
			Driver:  "json-file",
			Options: map[string]string{},
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

func TestCleanServiceNoFindings(t *testing.T) {
	c := collected(compose.Service{
		Name:  "clean",
		Image: "nginx:latest",
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Services[0].Findings))
	}
}
