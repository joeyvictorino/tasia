package configcheck

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(files ...compose.File) *collect.Collected {
	return &collect.Collected{Root: "/test", ComposeFiles: files}
}

func TestNoConflicts(t *testing.T) {
	c := makeCollected(compose.File{
		Path: "a/docker-compose.yml",
		Services: []compose.Service{
			{Name: "web", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80}}},
		},
	})
	r := CheckConflicts(c)
	if !r.Clean {
		t.Errorf("expected clean, got %d conflicts", len(r.Conflicts))
	}
}

func TestPortConflict(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path: "a/docker-compose.yml",
			Services: []compose.Service{
				{Name: "web", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 80}}},
			},
		},
		compose.File{
			Path: "b/docker-compose.yml",
			Services: []compose.Service{
				{Name: "api", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 3000}}},
			},
		},
	)
	r := CheckConflicts(c)
	if r.Clean {
		t.Fatal("expected conflicts")
	}
	found := false
	for _, c := range r.Conflicts {
		if c.Type == "port_conflict" {
			found = true
		}
	}
	if !found {
		t.Error("expected port_conflict type")
	}
}

func TestNameConflict(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path:     "a/docker-compose.yml",
			Services: []compose.Service{{Name: "redis"}},
		},
		compose.File{
			Path:     "b/docker-compose.yml",
			Services: []compose.Service{{Name: "redis"}},
		},
	)
	r := CheckConflicts(c)
	found := false
	for _, c := range r.Conflicts {
		if c.Type == "name_conflict" {
			found = true
		}
	}
	if !found {
		t.Error("expected name_conflict")
	}
}

func TestNetworkCollision(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path:     "a/docker-compose.yml",
			Networks: map[string]compose.Network{"backend": {}},
		},
		compose.File{
			Path:     "b/docker-compose.yml",
			Networks: map[string]compose.Network{"backend": {}},
		},
	)
	r := CheckConflicts(c)
	found := false
	for _, c := range r.Conflicts {
		if c.Type == "network_collision" {
			found = true
		}
	}
	if !found {
		t.Error("expected network_collision")
	}
}

func TestVolumeOverlap(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path: "a/docker-compose.yml",
			Services: []compose.Service{
				{Name: "web", Volumes: []string{"./data:/app/data"}},
			},
		},
		compose.File{
			Path: "b/docker-compose.yml",
			Services: []compose.Service{
				{Name: "worker", Volumes: []string{"./data:/worker/data"}},
			},
		},
	)
	r := CheckConflicts(c)
	found := false
	for _, c := range r.Conflicts {
		if c.Type == "volume_overlap" {
			found = true
		}
	}
	if !found {
		t.Error("expected volume_overlap")
	}
}

func TestEnvConflict(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path: "a/docker-compose.yml",
			Services: []compose.Service{
				{Name: "web", Environment: []string{"DB_HOST=localhost"}},
			},
		},
		compose.File{
			Path: "b/docker-compose.yml",
			Services: []compose.Service{
				{Name: "web", Environment: []string{"DB_HOST=db.internal"}},
			},
		},
	)
	r := CheckConflicts(c)
	found := false
	for _, c := range r.Conflicts {
		if c.Type == "env_conflict" {
			found = true
		}
	}
	if !found {
		t.Error("expected env_conflict")
	}
}

func TestSortBySeverity(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path: "a/docker-compose.yml",
			Services: []compose.Service{
				{Name: "web", Environment: []string{"X=1"}},
			},
			Networks: map[string]compose.Network{"net": {}},
		},
		compose.File{
			Path: "b/docker-compose.yml",
			Services: []compose.Service{
				{Name: "web", Environment: []string{"X=2"}, Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}},
			},
			Networks: map[string]compose.Network{"net": {}},
		},
		compose.File{
			Path: "c/docker-compose.yml",
			Services: []compose.Service{
				{Name: "api", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 3000}}},
			},
		},
	)
	r := CheckConflicts(c)
	if len(r.Conflicts) == 0 {
		t.Fatal("expected conflicts")
	}
	if r.Conflicts[0].Severity != "high" {
		t.Errorf("first conflict severity = %q, want high", r.Conflicts[0].Severity)
	}
}

func TestFormatTextClean(t *testing.T) {
	r := CheckResult{Path: "/test", Clean: true}
	out := FormatText(r)
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestFormatTextWithConflicts(t *testing.T) {
	r := CheckResult{
		Path: "/test",
		Conflicts: []Conflict{
			{Type: "port_conflict", Severity: "high", Message: "port 80 conflict", FileA: "a.yml", FileB: "b.yml", ServiceA: "web", ServiceB: "api"},
		},
	}
	out := FormatText(r)
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := makeCollected()
	r := CheckConflicts(c)
	if !r.Clean {
		t.Error("empty collected should be clean")
	}
}

func TestSameFileNoConflict(t *testing.T) {
	c := makeCollected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "web", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}},
			{Name: "api", Ports: []compose.PortMapping{{HostPort: 3000, TargetPort: 3000}}},
		},
		Networks: map[string]compose.Network{"default": {}},
	})
	r := CheckConflicts(c)
	portConflicts := 0
	for _, c := range r.Conflicts {
		if c.Type == "port_conflict" {
			portConflicts++
		}
	}
	if portConflicts > 0 {
		t.Error("different ports in same file should not conflict")
	}
}
