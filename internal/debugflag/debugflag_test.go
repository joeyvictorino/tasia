package debugflag

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func findRule(results []ServiceResult, rule string) bool {
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return true
			}
		}
	}
	return false
}

func TestDebugPortExposed5005(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "api",
		Ports: []compose.PortMapping{{HostPort: 5005, TargetPort: 5005, Raw: "5005:5005"}},
	})
	r := Analyze(c)
	if !findRule(r.Services, "debug_port_exposed") {
		t.Error("expected debug_port_exposed for port 5005")
	}
}

func TestDebugPort9229(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "node-app",
		Ports: []compose.PortMapping{{HostPort: 9229, TargetPort: 9229, Raw: "0.0.0.0:9229:9229"}},
	})
	r := Analyze(c)
	if !findRule(r.Services, "debug_port_exposed") {
		t.Error("expected debug_port_exposed for port 9229")
	}
}

func TestNonDebugPort(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "web",
		Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80, Raw: "8080:80"}},
	})
	r := Analyze(c)
	if findRule(r.Services, "debug_port_exposed") {
		t.Error("should not flag non-debug port 80")
	}
}

func TestDebugEnvFlaskDebug(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "flask-app",
		Environment: []string{"FLASK_DEBUG=true"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "debug_env_enabled") {
		t.Error("expected debug_env_enabled for FLASK_DEBUG=true")
	}
}

func TestDebugEnvNodeDebug(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "node-app",
		Environment: []string{"NODE_DEBUG=1"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "debug_env_enabled") {
		t.Error("expected debug_env_enabled for NODE_DEBUG=1")
	}
}

func TestDebugEnvNotTriggered(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"APP_NAME=myapp"},
	})
	r := Analyze(c)
	if findRule(r.Services, "debug_env_enabled") {
		t.Error("should not flag non-debug env var")
	}
}

func TestDebugEnvProductionValue(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"LOG_LEVEL=info"},
	})
	r := Analyze(c)
	if findRule(r.Services, "debug_env_enabled") {
		t.Error("should not flag LOG_LEVEL=info")
	}
}

func TestVerboseLoggingTrace(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"LOG_LEVEL=trace"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "debug_verbose_logging") {
		t.Error("expected debug_verbose_logging for LOG_LEVEL=trace")
	}
}

func TestVerboseLoggingDebug(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"LOGLEVEL=debug"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "debug_verbose_logging") {
		t.Error("expected debug_verbose_logging for LOGLEVEL=debug")
	}
}

func TestVerboseLoggingInfo(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"LOG_LEVEL=info"},
	})
	r := Analyze(c)
	if findRule(r.Services, "debug_verbose_logging") {
		t.Error("should not flag LOG_LEVEL=info")
	}
}

func TestDebugEntrypointInspect(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "node-app",
		Entrypoint: []string{"node", "--inspect=0.0.0.0:9229", "server.js"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "debug_entrypoint") {
		t.Error("expected debug_entrypoint for --inspect")
	}
}

func TestDebugEntrypointJDWP(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "java-app",
		Entrypoint: []string{"java", "-agentlib:jdwp=transport=dt_socket,server=y", "-jar", "app.jar"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "debug_entrypoint") {
		t.Error("expected debug_entrypoint for -agentlib:jdwp")
	}
}

func TestDebugEntrypointClean(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "app",
		Entrypoint: []string{"python", "-u", "main.py"},
	})
	r := Analyze(c)
	if findRule(r.Services, "debug_entrypoint") {
		t.Error("should not flag clean entrypoint")
	}
}

func TestDevModeDevelopment(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"NODE_ENV=development"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "debug_dev_mode") {
		t.Error("expected debug_dev_mode for NODE_ENV=development")
	}
}

func TestDevModeStaging(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"APP_STAGE=staging"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "debug_dev_mode") {
		t.Error("expected debug_dev_mode for APP_STAGE=staging")
	}
}

func TestDevModeProduction(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"NODE_ENV=production"},
	})
	r := Analyze(c)
	if findRule(r.Services, "debug_dev_mode") {
		t.Error("should not flag NODE_ENV=production")
	}
}

func TestPrivilegedWithDebug(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "debugger",
		Privileged: true,
		Ports:      []compose.PortMapping{{HostPort: 5005, TargetPort: 5005, Raw: "5005:5005"}},
	})
	r := Analyze(c)
	if !findRule(r.Services, "debug_privileged") {
		t.Error("expected debug_privileged for privileged + debug port")
	}
}

func TestPrivilegedWithoutDebug(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "infra",
		Privileged: true,
		Ports:      []compose.PortMapping{{HostPort: 8080, TargetPort: 80, Raw: "8080:80"}},
	})
	r := Analyze(c)
	if findRule(r.Services, "debug_privileged") {
		t.Error("should not flag privileged without debug features")
	}
}

func TestNoFindingsCleanService(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleServices(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "web"},
		compose.Service{Name: "api", Ports: []compose.PortMapping{{HostPort: 5005, TargetPort: 5005, Raw: "5005:5005"}}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "debug-svc",
		Privileged: true,
		Ports:      []compose.PortMapping{{HostPort: 9229, TargetPort: 9229, Raw: "9229:9229"}},
		Environment: []string{
			"FLASK_DEBUG=true",
			"LOG_LEVEL=trace",
			"NODE_ENV=development",
		},
		Entrypoint: []string{"node", "--inspect", "server.js"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 5 {
		t.Errorf("expected at least 5 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{Name: "api", Ports: []compose.PortMapping{{HostPort: 5005, TargetPort: 5005, Raw: "5005:5005"}}})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Debug Flag") {
		t.Error("expected 'Debug Flag' in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "no findings") {
		t.Error("expected 'no findings' in output")
	}
}

func TestReportPath(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.Path)
	}
}

