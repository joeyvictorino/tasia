package syslog

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

func TestIsSyslogPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/var/log/syslog", true},
		{"/var/log/messages", true},
		{"/var/log/auth.log", true},
		{"/var/log", true},
		{"/var/log/kern.log", true},
		{"/app/logs", false},
		{"/tmp/log", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isSyslogPath(tt.path)
		if got != tt.want {
			t.Errorf("isSyslogPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsSyslogSocket(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/dev/log", true},
		{"/var/run/syslog", true},
		{"/run/systemd/journal/syslog", true},
		{"/tmp/socket", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isSyslogSocket(tt.path)
		if got != tt.want {
			t.Errorf("isSyslogSocket(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsVerboseEnv(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"LOG_LEVEL=debug", true},
		{"LOG_LEVEL=TRACE", true},
		{"DEBUG=true", true},
		{"DEBUG=1", true},
		{"VERBOSE=true", true},
		{"LOG_LEVEL=info", false},
		{"APP_NAME=myapp", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isVerboseEnv(tt.env)
		if got != tt.want {
			t.Errorf("isVerboseEnv(%q) = %v, want %v", tt.env, got, tt.want)
		}
	}
}

func TestExtractVolumeSrc(t *testing.T) {
	tests := []struct {
		vol, want string
	}{
		{"/var/log:/container/log", "/var/log"},
		{"/var/log:/container/log:ro", "/var/log"},
		{"myvolume:/data", "myvolume"},
		{"/single", "/single"},
	}
	for _, tt := range tests {
		got := extractVolumeSrc(tt.vol)
		if got != tt.want {
			t.Errorf("extractVolumeSrc(%q) = %q, want %q", tt.vol, got, tt.want)
		}
	}
}

func TestExtractVolumeDst(t *testing.T) {
	tests := []struct {
		vol, want string
	}{
		{"/var/log:/container/log", "/container/log"},
		{"/var/log:/container/log:ro", "/container/log"},
		{"/single", ""},
	}
	for _, tt := range tests {
		got := extractVolumeDst(tt.vol)
		if got != tt.want {
			t.Errorf("extractVolumeDst(%q) = %q, want %q", tt.vol, got, tt.want)
		}
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestAnalyzeCleanService(t *testing.T) {
	s := svc("web")
	s.Volumes = []string{"/app/data:/data"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestHostSyslogMount(t *testing.T) {
	s := svc("logger")
	s.Volumes = []string{"/var/log/syslog:/container/syslog:ro"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "host_syslog_mount" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected host_syslog_mount finding")
	}
}

func TestHostVarLogMount(t *testing.T) {
	s := svc("monitor")
	s.Volumes = []string{"/var/log:/logs"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.HostSyslogMounts < 1 {
		t.Fatal("expected host_syslog_mount finding for /var/log")
	}
}

func TestSyslogSocketExposed(t *testing.T) {
	s := svc("syslog")
	s.Volumes = []string{"/dev/log:/dev/log"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "syslog_socket_exposed" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected syslog_socket_exposed finding")
	}
}

func TestVerboseLogging(t *testing.T) {
	s := svc("app")
	s.Environment = []string{"LOG_LEVEL=debug"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "verbose_logging" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected verbose_logging finding")
	}
}

func TestDebugEnvTrue(t *testing.T) {
	s := svc("debug-app")
	s.Environment = []string{"DEBUG=true"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.VerboseLogging < 1 {
		t.Fatal("expected verbose_logging finding for DEBUG=true")
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("full")
	s.Volumes = []string{"/var/log/syslog:/log", "/dev/log:/dev/log"}
	s.Environment = []string{"LOG_LEVEL=debug"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.HostSyslogMounts < 1 {
		t.Fatal("expected host syslog mount count > 0")
	}
	if r.Summary.SyslogSocketExposed < 1 {
		t.Fatal("expected syslog socket exposed count > 0")
	}
	if r.Summary.VerboseLogging < 1 {
		t.Fatal("expected verbose logging count > 0")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Fatal("expected non-empty text")
	}
	if !contains(text, "0 findings") {
		t.Fatal("expected 0 findings in text")
	}
}

func TestFormatTextWithFindings(t *testing.T) {
	s := svc("syslogger")
	s.Volumes = []string{"/var/log:/container/log"}
	c := collected(s)
	r := Analyze(c)
	text := FormatText(r)
	if !contains(text, "syslogger") {
		t.Fatal("expected service name in text")
	}
	if !contains(text, "Syslog Configuration") {
		t.Fatal("expected header in text")
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("a")
	s1.Volumes = []string{"/var/log/syslog:/log"}
	s2 := svc("b")
	s2.Volumes = []string{"/app/data:/data"}
	c := collected(s1, s2)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Fatalf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
