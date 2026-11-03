package loginjection

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: svcs},
		},
	}
}

func TestCleanService(t *testing.T) {
	svc := compose.Service{
		Name: "safe",
		Logging: &compose.LoggingConfig{
			Driver:  "json-file",
			Options: map[string]string{"max-size": "10m", "max-file": "3"},
		},
	}
	r := Analyze(collected(svc))
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestUnsafeLogDriverSyslog(t *testing.T) {
	svc := compose.Service{
		Name: "app",
		Logging: &compose.LoggingConfig{Driver: "syslog", Options: map[string]string{"max-size": "10m", "max-file": "3"}},
	}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unsafe_log_driver" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected unsafe_log_driver finding")
	}
}

func TestUnsafeLogDriverJournald(t *testing.T) {
	svc := compose.Service{
		Name: "app",
		Logging: &compose.LoggingConfig{Driver: "journald", Options: map[string]string{"max-size": "10m"}},
	}
	r := Analyze(collected(svc))
	if r.Summary.UnsafeLogDrivers != 1 {
		t.Errorf("expected 1 unsafe log driver, got %d", r.Summary.UnsafeLogDrivers)
	}
}

func TestUnsafeLogDriverGelf(t *testing.T) {
	svc := compose.Service{
		Name: "app",
		Logging: &compose.LoggingConfig{Driver: "gelf", Options: map[string]string{"max-size": "10m"}},
	}
	r := Analyze(collected(svc))
	if r.Summary.UnsafeLogDrivers != 1 {
		t.Errorf("expected 1 unsafe log driver, got %d", r.Summary.UnsafeLogDrivers)
	}
}

func TestMissingMaxSize(t *testing.T) {
	svc := compose.Service{
		Name:    "app",
		Logging: &compose.LoggingConfig{Driver: "json-file", Options: map[string]string{"max-file": "3"}},
	}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_log_size_limit" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_log_size_limit finding")
	}
}

func TestMissingMaxFile(t *testing.T) {
	svc := compose.Service{
		Name:    "app",
		Logging: &compose.LoggingConfig{Driver: "json-file", Options: map[string]string{"max-size": "10m"}},
	}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_log_file_limit" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_log_file_limit finding")
	}
}

func TestNoLoggingConfig(t *testing.T) {
	svc := compose.Service{Name: "app"}
	r := Analyze(collected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_logging_config" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected no_logging_config finding")
	}
}

func TestLogMountWritable(t *testing.T) {
	svc := compose.Service{
		Name:    "app",
		Volumes: []string{"/var/log:/var/log"},
		Logging: &compose.LoggingConfig{Driver: "json-file", Options: map[string]string{"max-size": "10m", "max-file": "3"}},
	}
	r := Analyze(collected(svc))
	if r.Summary.LogMountExposed != 1 {
		t.Errorf("expected 1 log mount exposed, got %d", r.Summary.LogMountExposed)
	}
}

func TestLogMountReadOnly(t *testing.T) {
	svc := compose.Service{
		Name:    "app",
		Volumes: []string{"/var/log:/var/log:ro"},
		Logging: &compose.LoggingConfig{Driver: "json-file", Options: map[string]string{"max-size": "10m", "max-file": "3"}},
	}
	r := Analyze(collected(svc))
	if r.Summary.LogMountExposed != 0 {
		t.Errorf("expected 0 writable log mounts, got %d", r.Summary.LogMountExposed)
	}
}

func TestDebugLogging(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"DEBUG=true"},
		Logging:     &compose.LoggingConfig{Driver: "json-file", Options: map[string]string{"max-size": "10m", "max-file": "3"}},
	}
	r := Analyze(collected(svc))
	if r.Summary.DebugLogEnabled != 1 {
		t.Errorf("expected 1 debug log, got %d", r.Summary.DebugLogEnabled)
	}
}

func TestDebugLogLevelTrace(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"LOG_LEVEL=trace"},
		Logging:     &compose.LoggingConfig{Driver: "json-file", Options: map[string]string{"max-size": "10m", "max-file": "3"}},
	}
	r := Analyze(collected(svc))
	if r.Summary.DebugLogEnabled != 1 {
		t.Errorf("expected 1 debug log, got %d", r.Summary.DebugLogEnabled)
	}
}

func TestLogPathTraversal(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"LOG_PATH=../../etc/passwd"},
		Logging:     &compose.LoggingConfig{Driver: "json-file", Options: map[string]string{"max-size": "10m", "max-file": "3"}},
	}
	r := Analyze(collected(svc))
	if r.Summary.EnvInLogPath != 1 {
		t.Errorf("expected 1 log path issue, got %d", r.Summary.EnvInLogPath)
	}
}

func TestLogPathAbsolute(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Environment: []string{"LOG_PATH=/var/log/app"},
		Logging:     &compose.LoggingConfig{Driver: "json-file", Options: map[string]string{"max-size": "10m", "max-file": "3"}},
	}
	r := Analyze(collected(svc))
	if r.Summary.EnvInLogPath != 1 {
		t.Errorf("expected 1 log path issue, got %d", r.Summary.EnvInLogPath)
	}
}

func TestMultipleServices(t *testing.T) {
	svc1 := compose.Service{
		Name:    "a",
		Logging: &compose.LoggingConfig{Driver: "syslog", Options: map[string]string{"max-size": "10m", "max-file": "3"}},
	}
	svc2 := compose.Service{
		Name:    "b",
		Logging: &compose.LoggingConfig{Driver: "fluentd", Options: map[string]string{"max-size": "10m", "max-file": "3"}},
	}
	r := Analyze(collected(svc1, svc2))
	if r.Summary.UnsafeLogDrivers != 2 {
		t.Errorf("expected 2 unsafe drivers, got %d", r.Summary.UnsafeLogDrivers)
	}
}

func TestSummaryTotals(t *testing.T) {
	svc := compose.Service{
		Name:        "app",
		Volumes:     []string{"/var/log:/var/log"},
		Environment: []string{"DEBUG=1"},
		Logging:     &compose.LoggingConfig{Driver: "syslog", Options: map[string]string{}},
	}
	r := Analyze(collected(svc))
	if r.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected multiple findings, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/empty"})
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for empty, got %d", r.Summary.TotalFindings)
	}
}

func TestDefaultDriverNoLimits(t *testing.T) {
	svc := compose.Service{
		Name:    "app",
		Logging: &compose.LoggingConfig{Driver: "", Options: map[string]string{}},
	}
	r := Analyze(collected(svc))
	found := 0
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_log_size_limit" || f.Rule == "missing_log_file_limit" {
				found++
			}
		}
	}
	if found != 2 {
		t.Errorf("expected 2 missing limit findings, got %d", found)
	}
}
