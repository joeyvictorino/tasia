package auditlog

import (
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

func svc(name string) compose.Service {
	return compose.Service{Name: name}
}

func TestLogDriver(t *testing.T) {
	tests := []struct {
		name string
		svc  compose.Service
		want string
	}{
		{"nil logging", svc("web"), ""},
		{"empty driver", compose.Service{Name: "web", Logging: &compose.LoggingConfig{}}, ""},
		{"json-file", compose.Service{Name: "web", Logging: &compose.LoggingConfig{Driver: "json-file"}}, "json-file"},
		{"SYSLOG uppercase", compose.Service{Name: "web", Logging: &compose.LoggingConfig{Driver: "SYSLOG"}}, "syslog"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := logDriver(tt.svc)
			if got != tt.want {
				t.Errorf("logDriver() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLogOpts(t *testing.T) {
	s := svc("web")
	if logOpts(s) != nil {
		t.Fatal("expected nil opts for service with no logging")
	}
	s.Logging = &compose.LoggingConfig{Options: map[string]string{"max-size": "10m"}}
	opts := logOpts(s)
	if opts["max-size"] != "10m" {
		t.Fatal("expected max-size option")
	}
}

func TestHasLogDriver(t *testing.T) {
	s := svc("web")
	if hasLogDriver(s) {
		t.Fatal("expected false for no logging config")
	}
	s.Logging = &compose.LoggingConfig{Driver: "syslog"}
	if !hasLogDriver(s) {
		t.Fatal("expected true for syslog driver")
	}
	s2 := svc("env")
	s2.Environment = []string{"LOG_DRIVER=fluentd"}
	if !hasLogDriver(s2) {
		t.Fatal("expected true for LOG_DRIVER env")
	}
}

func TestIsInsecureLogPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/dev/null", true},
		{"/tmp", true},
		{"/tmp/logs", true},
		{"/var/tmp", true},
		{"/dev/shm", true},
		{"/var/log", false},
		{"/app/logs", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isInsecureLogPath(tt.path)
		if got != tt.want {
			t.Errorf("isInsecureLogPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestHasLogMaxSize(t *testing.T) {
	s := svc("web")
	if hasLogMaxSize(s) {
		t.Fatal("expected false with no logging")
	}
	s.Logging = &compose.LoggingConfig{Options: map[string]string{"max-size": "10m"}}
	if !hasLogMaxSize(s) {
		t.Fatal("expected true with max-size set")
	}
}

func TestHasLogMaxFile(t *testing.T) {
	s := svc("web")
	if hasLogMaxFile(s) {
		t.Fatal("expected false with no logging")
	}
	s.Logging = &compose.LoggingConfig{Options: map[string]string{"max-file": "3"}}
	if !hasLogMaxFile(s) {
		t.Fatal("expected true with max-file set")
	}
}

func TestLogVolumeTargets(t *testing.T) {
	s := svc("web")
	s.Volumes = []string{"/data:/app", "/logs:/var/log/app", "/cache:/tmp"}
	targets := logVolumeTargets(s)
	if len(targets) != 1 {
		t.Fatalf("expected 1 log volume target, got %d", len(targets))
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestLoggingDisabled(t *testing.T) {
	s := svc("agent")
	s.Logging = &compose.LoggingConfig{Driver: "none"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "logging_disabled" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected logging_disabled finding")
	}
}

func TestUnboundedLogSize(t *testing.T) {
	s := svc("agent")
	s.Logging = &compose.LoggingConfig{Driver: "json-file"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unbounded_log_size" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected unbounded_log_size finding for json-file without max-size")
	}
}

func TestMissingLogRotation(t *testing.T) {
	s := svc("agent")
	s.Logging = &compose.LoggingConfig{Driver: "json-file"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_log_rotation" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected missing_log_rotation finding")
	}
}

func TestMaxSizeSuppressesUnbounded(t *testing.T) {
	s := svc("agent")
	s.Logging = &compose.LoggingConfig{
		Driver:  "json-file",
		Options: map[string]string{"max-size": "10m"},
	}
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unbounded_log_size" {
				t.Fatal("should not flag unbounded_log_size when max-size is set")
			}
		}
	}
}

func TestInsecureLogPath(t *testing.T) {
	s := svc("agent")
	s.Volumes = []string{"log-data:/dev/null"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "insecure_log_path" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected insecure_log_path finding")
	}
}

func TestReadonlyLogMount(t *testing.T) {
	s := svc("agent")
	s.Volumes = []string{"/data:/var/log/app:ro"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "readonly_log_mount" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected readonly_log_mount finding for read-only log volume")
	}
}

func TestNoLogConfiguration(t *testing.T) {
	s := svc("agent")
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_log_configuration" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected no_log_configuration finding")
	}
}

func TestLogDriverSuppressesNoConfig(t *testing.T) {
	s := svc("agent")
	s.Logging = &compose.LoggingConfig{Driver: "syslog"}
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_log_configuration" {
				t.Fatal("should not flag no_log_configuration when driver is set")
			}
		}
	}
}

func TestStdoutEnvSuppressesNoConfig(t *testing.T) {
	s := svc("agent")
	s.Environment = []string{"LOG_TO_STDOUT=true"}
	c := collected(s)
	r := Analyze(c)
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "no_log_configuration" {
				t.Fatal("should not flag no_log_configuration when LOG_TO_STDOUT is set")
			}
		}
	}
}

func TestDefaultDriverUnbounded(t *testing.T) {
	s := svc("agent")
	s.Logging = &compose.LoggingConfig{Driver: ""}
	c := collected(s)
	r := Analyze(c)
	foundUnbounded := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unbounded_log_size" {
				foundUnbounded = true
			}
		}
	}
	if !foundUnbounded {
		t.Fatal("expected unbounded_log_size for empty driver (default json-file)")
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("web")
	s1.Logging = &compose.LoggingConfig{Driver: "none"}
	s2 := svc("api")
	s2.Logging = &compose.LoggingConfig{Driver: "syslog"}
	c := collected(s1, s2)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.MissingLogConfig < 1 {
		t.Fatal("expected at least 1 missing log config (logging_disabled)")
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("agent")
	s.Logging = &compose.LoggingConfig{Driver: "none"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.MissingLogConfig < 1 {
		t.Fatal("expected MissingLogConfig >= 1")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/test"})
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text output")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	s := svc("agent")
	s.Logging = &compose.LoggingConfig{Driver: "none"}
	c := collected(s)
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text output")
	}
	if len(text) < 50 {
		t.Fatal("expected substantial text output")
	}
}

func TestDriverName(t *testing.T) {
	if driverName("") != "default (json-file)" {
		t.Fatal("expected default name for empty driver")
	}
	if driverName("syslog") != "syslog" {
		t.Fatal("expected syslog")
	}
}
