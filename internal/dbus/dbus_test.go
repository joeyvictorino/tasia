package dbus

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

func TestIsSystemBusPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/var/run/dbus/system_bus_socket", true},
		{"/run/dbus/system_bus_socket", true},
		{"/var/run/dbus", true},
		{"/run/dbus", true},
		{"/tmp/dbus-xxx", false},
		{"/app/data", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isSystemBusPath(tt.path)
		if got != tt.want {
			t.Errorf("isSystemBusPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsSessionBusPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/run/user/1000/bus", true},
		{"/tmp/dbus-abc123", true},
		{"/var/run/dbus", false},
		{"/app/data", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isSessionBusPath(tt.path)
		if got != tt.want {
			t.Errorf("isSessionBusPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsDBusEnv(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"DBUS_SYSTEM_BUS_ADDRESS=unix:path=/host/dbus", true},
		{"DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/bus", true},
		{"dbus_system_bus_address=unix:path=/dbus", true},
		{"APP_NAME=myapp", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isDBusEnv(tt.env)
		if got != tt.want {
			t.Errorf("isDBusEnv(%q) = %v, want %v", tt.env, got, tt.want)
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

func TestSystemBusExposed(t *testing.T) {
	s := svc("agent")
	s.Volumes = []string{"/var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "system_bus_exposed" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected system_bus_exposed finding")
	}
}

func TestRunDBusMount(t *testing.T) {
	s := svc("systemd")
	s.Volumes = []string{"/run/dbus:/run/dbus"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.SystemBusExposed < 1 {
		t.Fatal("expected system_bus_exposed for /run/dbus")
	}
}

func TestSessionBusExposed(t *testing.T) {
	s := svc("desktop")
	s.Volumes = []string{"/run/user/1000/bus:/run/user/1000/bus"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "session_bus_exposed" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected session_bus_exposed finding")
	}
}

func TestTmpDBusSession(t *testing.T) {
	s := svc("gui")
	s.Volumes = []string{"/tmp/dbus-abc123:/tmp/dbus-abc123"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.SessionBusExposed < 1 {
		t.Fatal("expected session_bus_exposed for /tmp/dbus-*")
	}
}

func TestDBusEnvConfig(t *testing.T) {
	s := svc("worker")
	s.Environment = []string{"DBUS_SYSTEM_BUS_ADDRESS=unix:path=/host/dbus"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "dbus_socket_mounted" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected dbus_socket_mounted finding")
	}
}

func TestPrivilegedDBusAccess(t *testing.T) {
	s := svc("privileged")
	s.CapAdd = []string{"SYS_ADMIN"}
	c := collected(s)
	r := Analyze(c)
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "privileged_dbus_access" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected privileged_dbus_access finding")
	}
}

func TestCapAllPrivileged(t *testing.T) {
	s := svc("allcaps")
	s.CapAdd = []string{"ALL"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.PrivilegedDBusAccess < 1 {
		t.Fatal("expected privileged_dbus_access for cap ALL")
	}
}

func TestSummaryCounts(t *testing.T) {
	s := svc("full")
	s.Volumes = []string{"/var/run/dbus:/dbus", "/run/user/1000:/session"}
	s.Environment = []string{"DBUS_SYSTEM_BUS_ADDRESS=unix:path=/x"}
	s.CapAdd = []string{"SYS_ADMIN"}
	c := collected(s)
	r := Analyze(c)
	if r.Summary.SystemBusExposed < 1 {
		t.Fatal("expected system bus count > 0")
	}
	if r.Summary.SessionBusExposed < 1 {
		t.Fatal("expected session bus count > 0")
	}
	if r.Summary.DBusSocketMounted < 1 {
		t.Fatal("expected dbus socket count > 0")
	}
	if r.Summary.PrivilegedDBusAccess < 1 {
		t.Fatal("expected privileged dbus count > 0")
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
	s := svc("dbus-test")
	s.Volumes = []string{"/var/run/dbus:/var/run/dbus"}
	c := collected(s)
	r := Analyze(c)
	text := FormatText(r)
	if !contains(text, "dbus-test") {
		t.Fatal("expected service name in text")
	}
	if !contains(text, "D-Bus Socket Exposure") {
		t.Fatal("expected header in text")
	}
}

func TestMultipleServices(t *testing.T) {
	s1 := svc("a")
	s1.Volumes = []string{"/var/run/dbus:/dbus"}
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
