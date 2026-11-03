package mergecheck

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(files ...compose.File) *collect.Collected {
	return &collect.Collected{Root: "/test", ComposeFiles: files}
}

func TestSingleFile(t *testing.T) {
	c := makeCollected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			{Name: "web", Image: "nginx:latest", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80, Raw: "80:80"}}},
		},
	})
	r := SimulateMerge(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	if r.Services[0].Image != "nginx:latest" {
		t.Errorf("image = %q, want nginx:latest", r.Services[0].Image)
	}
}

func TestMergeOverridesImage(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path:     "docker-compose.yml",
			Services: []compose.Service{{Name: "web", Image: "nginx:1.24"}},
		},
		compose.File{
			Path:     "docker-compose.override.yml",
			Services: []compose.Service{{Name: "web", Image: "nginx:1.25"}},
		},
	)
	r := SimulateMerge(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	if r.Services[0].Image != "nginx:1.25" {
		t.Errorf("image = %q, want nginx:1.25", r.Services[0].Image)
	}
	if len(r.Services[0].Overrides) != 1 {
		t.Errorf("expected 1 override, got %d", len(r.Services[0].Overrides))
	}
	if len(r.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(r.Warnings))
	}
}

func TestMergeEnvironmentOverride(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path:     "a.yml",
			Services: []compose.Service{{Name: "api", Environment: []string{"DB_HOST=localhost"}}},
		},
		compose.File{
			Path:     "b.yml",
			Services: []compose.Service{{Name: "api", Environment: []string{"DB_HOST=db.internal"}}},
		},
	)
	r := SimulateMerge(c)
	if r.Services[0].Environment["DB_HOST"] != "db.internal" {
		t.Errorf("DB_HOST = %q, want db.internal", r.Services[0].Environment["DB_HOST"])
	}
	if len(r.Services[0].Overrides) != 1 {
		t.Errorf("expected 1 override, got %d", len(r.Services[0].Overrides))
	}
}

func TestMergeCombinesPorts(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path:     "a.yml",
			Services: []compose.Service{{Name: "web", Ports: []compose.PortMapping{{HostPort: 80, TargetPort: 80, Raw: "80:80"}}}},
		},
		compose.File{
			Path:     "b.yml",
			Services: []compose.Service{{Name: "web", Ports: []compose.PortMapping{{HostPort: 443, TargetPort: 443, Raw: "443:443"}}}},
		},
	)
	r := SimulateMerge(c)
	if len(r.Services[0].Ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(r.Services[0].Ports))
	}
}

func TestMergeDeduplicatesVolumes(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path:     "a.yml",
			Services: []compose.Service{{Name: "web", Volumes: []string{"./data:/app/data"}}},
		},
		compose.File{
			Path:     "b.yml",
			Services: []compose.Service{{Name: "web", Volumes: []string{"./data:/app/data", "./logs:/app/logs"}}},
		},
	)
	r := SimulateMerge(c)
	if len(r.Services[0].Volumes) != 2 {
		t.Errorf("expected 2 unique volumes, got %d", len(r.Services[0].Volumes))
	}
}

func TestMultipleServices(t *testing.T) {
	c := makeCollected(
		compose.File{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "web", Image: "nginx"},
				{Name: "api", Image: "node"},
			},
		},
	)
	r := SimulateMerge(c)
	if len(r.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(r.Services))
	}
}

func TestEmptyCollected(t *testing.T) {
	c := makeCollected()
	r := SimulateMerge(c)
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := makeCollected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{{Name: "web", Image: "nginx"}},
	})
	r := SimulateMerge(c)
	out := FormatText(r)
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestFormatJSONOutput(t *testing.T) {
	c := makeCollected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{{Name: "web", Image: "nginx"}},
	})
	r := SimulateMerge(c)
	out, err := FormatJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if out == "" {
		t.Error("expected non-empty output")
	}
}
