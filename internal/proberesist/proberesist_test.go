package proberesist

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

func TestDebugPortExposed(t *testing.T) {
	c := collected(compose.Service{
		Name: "agent",
		Ports: []compose.PortMapping{
			{HostPort: 9229, TargetPort: 9229, Raw: "9229:9229"},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "proberesist_debug_port") {
		t.Error("expected proberesist_debug_port for Node.js inspector port 9229")
	}
	if r.Summary.DebugEndpoints < 1 {
		t.Errorf("expected debug endpoints >= 1, got %d", r.Summary.DebugEndpoints)
	}
}

func TestGoDelvePort(t *testing.T) {
	c := collected(compose.Service{
		Name: "api",
		Ports: []compose.PortMapping{
			{HostPort: 2345, TargetPort: 2345, Raw: "2345:2345"},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "proberesist_debug_port") {
		t.Error("expected proberesist_debug_port for Go delve debugger port")
	}
}

func TestPprofPort(t *testing.T) {
	c := collected(compose.Service{
		Name: "metrics",
		Ports: []compose.PortMapping{
			{HostPort: 6060, TargetPort: 6060, Raw: "6060:6060"},
		},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "proberesist_debug_port") {
		t.Error("expected proberesist_debug_port for Go pprof port")
	}
}

func TestSafePortNotFlagged(t *testing.T) {
	c := collected(compose.Service{
		Name: "web",
		Ports: []compose.PortMapping{
			{HostPort: 443, TargetPort: 443, Raw: "443:443"},
		},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "proberesist_debug_port") {
		t.Error("port 443 should not be flagged as debug port")
	}
}

func TestDebugEnvEnabled(t *testing.T) {
	c := collected(compose.Service{
		Name:        "app",
		Environment: []string{"DEBUG=true"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "proberesist_debug_enabled") {
		t.Error("expected proberesist_debug_enabled for DEBUG=true")
	}
}

func TestFlaskDebug(t *testing.T) {
	c := collected(compose.Service{
		Name:        "flask",
		Environment: []string{"FLASK_DEBUG=1"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "proberesist_debug_enabled") {
		t.Error("expected proberesist_debug_enabled for FLASK_DEBUG=1")
	}
}

func TestNodeDevEnv(t *testing.T) {
	c := collected(compose.Service{
		Name:        "node",
		Environment: []string{"NODE_ENV=development"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "proberesist_debug_enabled") {
		t.Error("expected proberesist_debug_enabled for NODE_ENV=development")
	}
}

func TestVersionHeaderExposure(t *testing.T) {
	c := collected(compose.Service{
		Name:        "proxy",
		Environment: []string{"SERVER_TOKENS=on"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "proberesist_version_header") {
		t.Error("expected proberesist_version_header for SERVER_TOKENS=on")
	}
	if r.Summary.VersionHeaders < 1 {
		t.Errorf("expected version headers >= 1, got %d", r.Summary.VersionHeaders)
	}
}

func TestStackTraceLeak(t *testing.T) {
	c := collected(compose.Service{
		Name:        "api",
		Environment: []string{"SHOW_ERRORS=true"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "proberesist_stack_trace") {
		t.Error("expected proberesist_stack_trace for SHOW_ERRORS=true")
	}
	if r.Summary.StackTraceLeaks < 1 {
		t.Errorf("expected stack trace leaks >= 1, got %d", r.Summary.StackTraceLeaks)
	}
}

func TestRustBacktrace(t *testing.T) {
	c := collected(compose.Service{
		Name:        "rust-svc",
		Environment: []string{"RUST_BACKTRACE=full"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "proberesist_stack_trace") {
		t.Error("expected proberesist_stack_trace for RUST_BACKTRACE=full")
	}
}

func TestStatusEndpoint(t *testing.T) {
	c := collected(compose.Service{
		Name:        "backend",
		Environment: []string{"STATUS_ENDPOINT=/debug/vars"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "proberesist_status_endpoint") {
		t.Error("expected proberesist_status_endpoint for /debug/vars endpoint")
	}
}

func TestHealthEndpointSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:        "backend",
		Environment: []string{"STATUS_ENDPOINT=/healthz"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "proberesist_status_endpoint") {
		t.Error("health endpoint should not be flagged")
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{
		Name:  "clean",
		Image: "nginx:latest",
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for clean service, got %d", len(r.Services[0].Findings))
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
		Name:        "agent",
		Environment: []string{"DEBUG=true"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name:        "svc",
		Environment: []string{"FLASK_DEBUG=1"},
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

func TestMultipleFindings(t *testing.T) {
	c := collected(compose.Service{
		Name: "allbad",
		Ports: []compose.PortMapping{
			{HostPort: 9229, TargetPort: 9229, Raw: "9229:9229"},
		},
		Environment: []string{"DEBUG=true", "SHOW_ERRORS=true", "SERVER_TOKENS=on"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}
