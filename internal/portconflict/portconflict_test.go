package portconflict

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalPorts != 0 {
		t.Fatalf("expected 0, got %d", r.Summary.TotalPorts)
	}
	if len(r.Conflicts) != 0 {
		t.Fatalf("expected 0 conflicts, got %d", len(r.Conflicts))
	}
}

func TestNoPorts(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "compose.yml",
			Services: []compose.Service{{Name: "app", Image: "node:20"}},
		}},
	}
	r := Analyze(c)
	if r.Summary.TotalPorts != 0 {
		t.Errorf("expected 0 ports, got %d", r.Summary.TotalPorts)
	}
}

func TestSinglePort(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "compose.yml",
			Services: []compose.Service{{
				Name: "web", Image: "nginx:1.25",
				Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80}},
			}},
		}},
	}
	r := Analyze(c)
	if r.Summary.TotalPorts != 1 {
		t.Errorf("expected 1, got %d", r.Summary.TotalPorts)
	}
	if r.Summary.Conflicts != 0 {
		t.Errorf("expected 0 conflicts, got %d", r.Summary.Conflicts)
	}
}

func TestConflictSamePort(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "compose.yml",
			Services: []compose.Service{
				{Name: "web1", Image: "nginx:1.25", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80}}},
				{Name: "web2", Image: "nginx:1.25", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80}}},
			},
		}},
	}
	r := Analyze(c)
	if r.Summary.Conflicts == 0 {
		t.Error("expected conflict for duplicate port 8080")
	}
	if r.Summary.CriticalCount == 0 {
		t.Error("expected critical severity for same-IP conflict")
	}
}

func TestNoConflictDifferentPorts(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "compose.yml",
			Services: []compose.Service{
				{Name: "web", Image: "nginx:1.25", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80}}},
				{Name: "api", Image: "node:20", Ports: []compose.PortMapping{{HostPort: 3000, TargetPort: 3000}}},
			},
		}},
	}
	r := Analyze(c)
	if r.Summary.Conflicts != 0 {
		t.Errorf("expected 0 conflicts, got %d", r.Summary.Conflicts)
	}
}

func TestConflictAcrossFiles(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "base.yml", Services: []compose.Service{
				{Name: "web", Image: "nginx:1.25", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}},
			}},
			{Path: "override.yml", Services: []compose.Service{
				{Name: "proxy", Image: "traefik:v2", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 8080}}},
			}},
		},
	}
	r := Analyze(c)
	if r.Summary.Conflicts == 0 {
		t.Error("expected cross-file port conflict")
	}
}

func TestPortsSortedInOutput(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "compose.yml",
			Services: []compose.Service{
				{Name: "b", Image: "x:1", Ports: []compose.PortMapping{{HostPort: 9000, TargetPort: 80}}},
				{Name: "a", Image: "x:1", Ports: []compose.PortMapping{{HostPort: 3000, TargetPort: 80}}},
			},
		}},
	}
	r := Analyze(c)
	if len(r.AllPorts) >= 2 {
		if r.AllPorts[0].HostPort > r.AllPorts[1].HostPort {
			t.Error("ports not sorted by host port")
		}
	}
}

func TestSkipsZeroPort(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "compose.yml",
			Services: []compose.Service{{
				Name: "app", Image: "x:1",
				Ports: []compose.PortMapping{{HostPort: 0, TargetPort: 80}},
			}},
		}},
	}
	r := Analyze(c)
	if r.Summary.TotalPorts != 0 {
		t.Errorf("expected 0 ports (zero host port), got %d", r.Summary.TotalPorts)
	}
}

func TestMultipleConflicts(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "compose.yml",
			Services: []compose.Service{
				{Name: "a", Image: "x:1", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}},
				{Name: "b", Image: "x:1", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}},
				{Name: "c", Image: "x:1", Ports: []compose.PortMapping{{HostPort: 443, TargetPort: 443}}},
				{Name: "d", Image: "x:1", Ports: []compose.PortMapping{{HostPort: 443, TargetPort: 443}}},
			},
		}},
	}
	r := Analyze(c)
	if r.Summary.Conflicts < 2 {
		t.Errorf("expected at least 2 conflicts, got %d", r.Summary.Conflicts)
	}
}

func TestFormatText(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "compose.yml",
			Services: []compose.Service{
				{Name: "web1", Image: "x:1", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80}}},
				{Name: "web2", Image: "x:1", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80}}},
			},
		}},
	}
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Port Conflict") {
		t.Error("missing header")
	}
	if !strings.Contains(text, "8080") {
		t.Error("missing port number")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	text := FormatText(r)
	if !strings.Contains(text, "No port bindings") {
		t.Error("missing empty message")
	}
}

func TestFormatJSON(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Path: "compose.yml",
			Services: []compose.Service{
				{Name: "web", Image: "x:1", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}},
			},
		}},
	}
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if parsed.Summary.TotalPorts != 1 {
		t.Error("unexpected total_ports in JSON")
	}
}
