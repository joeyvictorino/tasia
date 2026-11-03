package portrange

import (
	"fmt"
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

func TestWidePortRange(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "web",
		Ports: []compose.PortMapping{pm(8000, 8000, "8000-9000:8000-9000")},
	})
	r := Analyze(c)
	if !findRule(r.Services, "port_wide_range") {
		t.Error("expected port_wide_range for range mapping")
	}
}

func TestSinglePortNotWide(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "web",
		Ports: []compose.PortMapping{pm(8080, 8080, "8080:8080")},
	})
	r := Analyze(c)
	if findRule(r.Services, "port_wide_range") {
		t.Error("should not flag single port as wide range")
	}
}

func TestOverlappingPorts(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "web1", Ports: []compose.PortMapping{pm(8080, 80, "8080:80")}},
		compose.Service{Name: "web2", Ports: []compose.PortMapping{pm(8080, 80, "8080:80")}},
	)
	r := Analyze(c)
	if !findRule(r.Services, "port_overlapping") {
		t.Error("expected port_overlapping for conflicting host ports")
	}
}

func TestNoOverlapDifferentPorts(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "web1", Ports: []compose.PortMapping{pm(8080, 80, "8080:80")}},
		compose.Service{Name: "web2", Ports: []compose.PortMapping{pm(8081, 80, "8081:80")}},
	)
	r := Analyze(c)
	if findRule(r.Services, "port_overlapping") {
		t.Error("should not flag different host ports as overlapping")
	}
}

func TestHighPortCount(t *testing.T) {
	ports := make([]compose.PortMapping, 12)
	for i := range ports {
		p := 3000 + i
		ports[i] = pm(p, p, fmt.Sprintf("%d:%d", p, p))
	}
	c := mkCollected(compose.Service{Name: "mega", Ports: ports})
	r := Analyze(c)
	if !findRule(r.Services, "port_high_count") {
		t.Error("expected port_high_count for 12 exposed ports")
	}
}

func TestNormalPortCount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "app",
		Ports: []compose.PortMapping{pm(8080, 8080, "8080:8080"), pm(8443, 8443, "8443:8443")},
	})
	r := Analyze(c)
	if findRule(r.Services, "port_high_count") {
		t.Error("should not flag 2 ports as high count")
	}
}

func TestEphemeralPortRange(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "app",
		Ports: []compose.PortMapping{pm(50000, 8080, "50000:8080")},
	})
	r := Analyze(c)
	if !findRule(r.Services, "port_ephemeral_range") {
		t.Error("expected port_ephemeral_range for port 50000")
	}
}

func TestNonEphemeralPort(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "app",
		Ports: []compose.PortMapping{pm(8080, 8080, "8080:8080")},
	})
	r := Analyze(c)
	if findRule(r.Services, "port_ephemeral_range") {
		t.Error("should not flag port 8080 as ephemeral")
	}
}

func TestSensitivePortMySQL(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "db",
		Ports: []compose.PortMapping{pm(3306, 3306, "3306:3306")},
	})
	r := Analyze(c)
	if !findRule(r.Services, "port_sensitive") {
		t.Error("expected port_sensitive for MySQL port 3306")
	}
}

func TestSensitivePortRedis(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "cache",
		Ports: []compose.PortMapping{pm(6379, 6379, "6379:6379")},
	})
	r := Analyze(c)
	if !findRule(r.Services, "port_sensitive") {
		t.Error("expected port_sensitive for Redis port 6379")
	}
}

func TestNonSensitivePort(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "app",
		Ports: []compose.PortMapping{pm(8080, 8080, "8080:8080")},
	})
	r := Analyze(c)
	if findRule(r.Services, "port_sensitive") {
		t.Error("should not flag port 8080 as sensitive")
	}
}

func TestDuplicateExpose(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "app",
		Ports: []compose.PortMapping{pm(8080, 80, "8080:80"), pm(8080, 443, "8080:443")},
	})
	r := Analyze(c)
	if !findRule(r.Services, "port_duplicate_expose") {
		t.Error("expected port_duplicate_expose for duplicate host port")
	}
}

func TestNoDuplicateExpose(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:  "app",
		Ports: []compose.PortMapping{pm(8080, 80, "8080:80"), pm(8443, 443, "8443:443")},
	})
	r := Analyze(c)
	if findRule(r.Services, "port_duplicate_expose") {
		t.Error("should not flag different host ports as duplicate")
	}
}

func TestFormatTextHeader(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Ports: []compose.PortMapping{pm(3306, 3306, "3306:3306")}})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Port Range") {
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
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "db", Ports: []compose.PortMapping{pm(3306, 3306, "3306:3306")}},
		compose.Service{Name: "cache", Ports: []compose.PortMapping{pm(6379, 6379, "6379:6379")}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.SensitivePort < 2 {
		t.Errorf("expected at least 2 sensitive port findings, got %d", r.Summary.SensitivePort)
	}
}
