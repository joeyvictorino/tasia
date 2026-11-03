package socketbind

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func pm(hostPort, targetPort int, raw string) compose.PortMapping {
	return compose.PortMapping{HostPort: hostPort, TargetPort: targetPort, Raw: raw}
}

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

func countRule(results []ServiceResult, rule string) int {
	n := 0
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				n++
			}
		}
	}
	return n
}

func TestWildcardBindAllInterfaces(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "web",
		Environment: []string{"BIND_ADDR=0.0.0.0"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "socket_wildcard_bind") {
		t.Error("expected socket_wildcard_bind for 0.0.0.0")
	}
}

func TestWildcardBindIPv6(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Command: []string{"server", "--bind", "[::]"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "socket_wildcard_bind") {
		t.Error("expected socket_wildcard_bind for [::]")
	}
}

func TestNoWildcardBind(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "web",
		Environment: []string{"BIND_ADDR=127.0.0.1"},
	})
	r := Analyze(c)
	if findRule(r.Services, "socket_wildcard_bind") {
		t.Error("should not flag localhost binding")
	}
}

func TestPrivilegedPort(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "web",
		Ports: []compose.PortMapping{pm(80, 8080, "80:8080")},
	})
	r := Analyze(c)
	if !findRule(r.Services, "socket_privileged_port") {
		t.Error("expected socket_privileged_port for port 80")
	}
}

func TestPrivilegedPortSSL(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "web",
		Ports: []compose.PortMapping{pm(443, 8443, "443:8443")},
	})
	r := Analyze(c)
	if !findRule(r.Services, "socket_privileged_port") {
		t.Error("expected socket_privileged_port for port 443")
	}
}

func TestNonPrivilegedPort(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "web",
		Ports: []compose.PortMapping{pm(8080, 8080, "8080:8080")},
	})
	r := Analyze(c)
	if findRule(r.Services, "socket_privileged_port") {
		t.Error("should not flag non-privileged port 8080")
	}
}

func TestDebugPort9229(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "node-app",
		Ports: []compose.PortMapping{pm(9229, 9229, "9229:9229")},
	})
	r := Analyze(c)
	if !findRule(r.Services, "socket_debug_port") {
		t.Error("expected socket_debug_port for Node.js debug port 9229")
	}
}

func TestDebugPort5005(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "java-app",
		Ports: []compose.PortMapping{pm(5005, 5005, "5005:5005")},
	})
	r := Analyze(c)
	if !findRule(r.Services, "socket_debug_port") {
		t.Error("expected socket_debug_port for Java debug port 5005")
	}
}

func TestNonDebugPort(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "app",
		Ports: []compose.PortMapping{pm(3000, 3000, "3000:3000")},
	})
	r := Analyze(c)
	if findRule(r.Services, "socket_debug_port") {
		t.Error("should not flag non-debug port 3000")
	}
}

func TestUDPExposed(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "dns",
		Ports: []compose.PortMapping{pm(53, 53, "53:53/udp")},
	})
	r := Analyze(c)
	if !findRule(r.Services, "socket_udp_exposed") {
		t.Error("expected socket_udp_exposed for UDP port")
	}
}

func TestTCPNotFlaggedUDP(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "web",
		Ports: []compose.PortMapping{pm(8080, 8080, "8080:8080")},
	})
	r := Analyze(c)
	if findRule(r.Services, "socket_udp_exposed") {
		t.Error("should not flag TCP port as UDP")
	}
}

func TestHostNetworkMode(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "monitor",
		NetworkMode: "host",
	})
	r := Analyze(c)
	if !findRule(r.Services, "socket_host_net_bind") {
		t.Error("expected socket_host_net_bind for host network mode")
	}
}

func TestBridgeNetworkMode(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "web",
		NetworkMode: "bridge",
	})
	r := Analyze(c)
	if findRule(r.Services, "socket_host_net_bind") {
		t.Error("should not flag bridge network mode")
	}
}

func TestMissingHostMapping(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "app",
		Ports: []compose.PortMapping{pm(0, 8080, "8080")},
	})
	r := Analyze(c)
	if !findRule(r.Services, "socket_missing_host_mapping") {
		t.Error("expected socket_missing_host_mapping for container-only port")
	}
}

func TestPrivilegedPortFromEnv(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"PORT=80"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "socket_privileged_port") {
		t.Error("expected socket_privileged_port from PORT=80 env")
	}
}

func TestSummaryCount(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "web", Ports: []compose.PortMapping{pm(80, 8080, "80:8080"), pm(9229, 9229, "9229:9229")}},
		compose.Service{Name: "dns", Ports: []compose.PortMapping{pm(53, 53, "53:53/udp")}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Ports: []compose.PortMapping{pm(80, 8080, "80:8080")}})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Socket Binding") {
		t.Error("expected header in text output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "clean"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "(no findings)") {
		t.Error("expected no findings message")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for empty collected, got %d", r.Summary.TotalFindings)
	}
}

func TestMultipleFindings(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "risky",
		Ports:       []compose.PortMapping{pm(53, 53, "53:53/udp"), pm(80, 8080, "80:8080")},
		NetworkMode: "host",
		Environment: []string{"BIND=0.0.0.0"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 4 {
		t.Errorf("expected at least 4 findings for risky service, got %d", r.Summary.TotalFindings)
	}
}
