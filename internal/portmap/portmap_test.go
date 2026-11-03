package portmap

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(files ...compose.File) *collect.Collected {
	return &collect.Collected{Root: "/test", ComposeFiles: files}
}

func TestSinglePort(t *testing.T) {
	c := makeCollected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "web", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}},
		},
	})
	r := Analyze(c)
	if len(r.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(r.Entries))
	}
	if r.Entries[0].HostIP != "0.0.0.0" {
		t.Errorf("host IP = %q, want 0.0.0.0", r.Entries[0].HostIP)
	}
}

func TestPortClash(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path:     "a.yml",
			Services: []compose.Service{{Name: "web", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}}},
		},
		compose.File{
			Path:     "b.yml",
			Services: []compose.Service{{Name: "api", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 3000}}}},
		},
	)
	r := Analyze(c)
	if len(r.Clashes) != 1 {
		t.Fatalf("expected 1 clash, got %d", len(r.Clashes))
	}
	if r.Clashes[0].HostPort != 80 {
		t.Errorf("clash port = %d, want 80", r.Clashes[0].HostPort)
	}
	if len(r.Clashes[0].Owners) != 2 {
		t.Errorf("expected 2 owners, got %d", len(r.Clashes[0].Owners))
	}
}

func TestNoClashes(t *testing.T) {
	c := makeCollected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "web", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}},
			{Name: "api", Ports: []compose.PortMapping{{HostPort: 3000, TargetPort: 3000}}},
		},
	})
	r := Analyze(c)
	if len(r.Clashes) != 0 {
		t.Errorf("expected 0 clashes, got %d", len(r.Clashes))
	}
}

func TestDifferentInterfaces(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path:     "a.yml",
			Services: []compose.Service{{Name: "web", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80, HostIP: "127.0.0.1"}}}},
		},
		compose.File{
			Path:     "b.yml",
			Services: []compose.Service{{Name: "api", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 3000, HostIP: "192.168.1.1"}}}},
		},
	)
	r := Analyze(c)
	if len(r.Clashes) != 0 {
		t.Errorf("different interfaces should not clash, got %d clashes", len(r.Clashes))
	}
}

func TestSortedByPort(t *testing.T) {
	c := makeCollected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "api", Ports: []compose.PortMapping{{HostPort: 3000, TargetPort: 3000}}},
			{Name: "web", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}},
		},
	})
	r := Analyze(c)
	if r.Entries[0].HostPort != 80 {
		t.Errorf("first entry port = %d, want 80", r.Entries[0].HostPort)
	}
}

func TestSkipsZeroPorts(t *testing.T) {
	c := makeCollected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "web", Ports: []compose.PortMapping{{HostPort: 0, TargetPort: 80}}},
		},
	})
	r := Analyze(c)
	if len(r.Entries) != 0 {
		t.Errorf("expected 0 entries for zero port, got %d", len(r.Entries))
	}
}

func TestEmptyCollected(t *testing.T) {
	c := makeCollected()
	r := Analyze(c)
	if len(r.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(r.Entries))
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := makeCollected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{{Name: "web", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}}},
	})
	r := Analyze(c)
	out := FormatText(r)
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestFormatJSONOutput(t *testing.T) {
	c := makeCollected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{{Name: "web", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80}}}},
	})
	r := Analyze(c)
	out, err := FormatJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if out == "" {
		t.Error("expected non-empty output")
	}
}
