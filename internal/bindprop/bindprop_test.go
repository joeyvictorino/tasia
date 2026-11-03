package bindprop

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

func TestNoVolumes(t *testing.T) {
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for service with no volumes, got %d", len(r.Services[0].Findings))
	}
}

func TestDefaultPropagation(t *testing.T) {
	c := collected(compose.Service{
		Name:    "web",
		Volumes: []string{"./data:/app/data"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "bindprop_default_propagation" {
			found = true
		}
	}
	if !found {
		t.Error("expected bindprop_default_propagation finding for bind mount without explicit propagation")
	}
}

func TestSharedPropagation(t *testing.T) {
	c := collected(compose.Service{
		Name:    "agent",
		Volumes: []string{"./data:/app/data:rw,rshared"},
	})
	r := Analyze(c)
	foundShared := false
	foundSharedRW := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "bindprop_shared_mount" {
			foundShared = true
		}
		if f.Rule == "bindprop_shared_rw" {
			foundSharedRW = true
		}
	}
	if !foundShared {
		t.Error("expected bindprop_shared_mount finding")
	}
	if !foundSharedRW {
		t.Error("expected bindprop_shared_rw finding for rw+rshared")
	}
}

func TestSharedReadOnly(t *testing.T) {
	c := collected(compose.Service{
		Name:    "agent",
		Volumes: []string{"./data:/app/data:ro,shared"},
	})
	r := Analyze(c)
	foundShared := false
	foundSharedRW := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "bindprop_shared_mount" {
			foundShared = true
		}
		if f.Rule == "bindprop_shared_rw" {
			foundSharedRW = true
		}
	}
	if !foundShared {
		t.Error("expected bindprop_shared_mount even for ro shared")
	}
	if foundSharedRW {
		t.Error("should NOT flag shared_rw for read-only shared mount")
	}
}

func TestSlavePropagation(t *testing.T) {
	c := collected(compose.Service{
		Name:    "worker",
		Volumes: []string{"/host/path:/container/path:rslave"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "bindprop_slave_mount" {
			found = true
		}
	}
	if !found {
		t.Error("expected bindprop_slave_mount finding for rslave propagation")
	}
}

func TestPrivateNonRecursive(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"./data:/app/data:private"},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Services[0].Findings {
		if f.Rule == "bindprop_non_recursive" {
			found = true
		}
	}
	if !found {
		t.Error("expected bindprop_non_recursive finding for 'private' mode")
	}
}

func TestRprivateSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"./data:/app/data:rprivate"},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Rule == "bindprop_shared_mount" || f.Rule == "bindprop_slave_mount" || f.Rule == "bindprop_non_recursive" {
			t.Errorf("unexpected finding for rprivate: %s", f.Rule)
		}
	}
}

func TestNamedVolumeSkipped(t *testing.T) {
	c := collected(compose.Service{
		Name:    "db",
		Volumes: []string{"pgdata:/var/lib/postgres"},
	})
	r := Analyze(c)
	for _, f := range r.Services[0].Findings {
		if f.Rule == "bindprop_default_propagation" {
			t.Error("should not flag default propagation for named volumes (not bind mounts)")
		}
	}
}

func TestSummary(t *testing.T) {
	c := collected(
		compose.Service{
			Name:    "web",
			Volumes: []string{"./data:/app/data:rshared"},
		},
		compose.Service{
			Name:    "api",
			Volumes: []string{"./logs:/var/log:rslave"},
		},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.TotalMounts != 2 {
		t.Errorf("expected 2 mounts, got %d", r.Summary.TotalMounts)
	}
	if r.Summary.SharedMounts != 1 {
		t.Errorf("expected 1 shared mount, got %d", r.Summary.SharedMounts)
	}
	if r.Summary.UnsafePropagation != 2 {
		t.Errorf("expected 2 unsafe propagation, got %d", r.Summary.UnsafePropagation)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name:    "web",
		Volumes: []string{"./data:/app/data:rshared"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !contains(text, "Bind Mount Propagation") {
		t.Error("expected header in text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name:    "web",
		Volumes: []string{"./data:/app/data"},
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

func TestEmptyServices(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
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
