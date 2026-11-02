package volumeaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(files ...compose.File) *collect.Collected {
	return &collect.Collected{Root: "/test", ComposeFiles: files}
}

func svc(name string, vols ...string) compose.Service {
	return compose.Service{Name: name, Volumes: vols}
}

func TestEmptyCollected(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.VolumesScanned != 0 {
		t.Fatalf("expected 0 volumes, got %d", r.Summary.VolumesScanned)
	}
	if r.Summary.FindingCount != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.FindingCount)
	}
}

func TestNoVolumes(t *testing.T) {
	c := collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{{Name: "web"}},
	})
	r := Analyze(c)
	if r.Summary.VolumesScanned != 0 {
		t.Fatalf("expected 0 volumes, got %d", r.Summary.VolumesScanned)
	}
}

func TestWritableDockerSocket(t *testing.T) {
	c := collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{svc("agent", "/var/run/docker.sock:/var/run/docker.sock")},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "writable_docker_socket" && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected writable_docker_socket finding")
	}
}

func TestReadOnlyDockerSocketNoFinding(t *testing.T) {
	c := collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{svc("agent", "/var/run/docker.sock:/var/run/docker.sock:ro")},
	})
	r := Analyze(c)
	for _, f := range r.Findings {
		if f.Category == "writable_docker_socket" {
			t.Fatal("should not flag read-only docker socket")
		}
	}
}

func TestSharedWritableVolume(t *testing.T) {
	c := collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			svc("app", "data:/data"),
			svc("worker", "data:/data"),
		},
	})
	r := Analyze(c)
	if len(r.SharedVolumes) != 1 {
		t.Fatalf("expected 1 shared volume, got %d", len(r.SharedVolumes))
	}
	if !r.SharedVolumes[0].Writable {
		t.Fatal("expected shared volume to be writable")
	}
	found := false
	for _, f := range r.Findings {
		if f.Category == "shared_writable_volume" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected shared_writable_volume finding")
	}
}

func TestSharedReadOnlyNoFinding(t *testing.T) {
	c := collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			svc("app", "config:/config:ro"),
			svc("worker", "config:/config:ro"),
		},
	})
	r := Analyze(c)
	if len(r.SharedVolumes) != 1 {
		t.Fatalf("expected 1 shared volume, got %d", len(r.SharedVolumes))
	}
	for _, f := range r.Findings {
		if f.Category == "shared_writable_volume" {
			t.Fatal("should not flag read-only shared volume")
		}
	}
}

func TestPathOverlap(t *testing.T) {
	c := collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			svc("app", "/data:/data"),
			svc("worker", "/data/logs:/logs"),
		},
	})
	r := Analyze(c)
	if len(r.Overlaps) != 1 {
		t.Fatalf("expected 1 overlap, got %d", len(r.Overlaps))
	}
	if r.Overlaps[0].Overlap != "/data" {
		t.Fatalf("expected overlap /data, got %s", r.Overlaps[0].Overlap)
	}
}

func TestNoOverlapDifferentPaths(t *testing.T) {
	c := collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			svc("app", "/data:/data"),
			svc("worker", "/logs:/logs"),
		},
	})
	r := Analyze(c)
	if len(r.Overlaps) != 0 {
		t.Fatalf("expected 0 overlaps, got %d", len(r.Overlaps))
	}
}

func TestRootTargetWritable(t *testing.T) {
	c := collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{svc("app", "/host-etc:/etc")},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "root_target_writable" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected root_target_writable finding")
	}
}

func TestIdentityMount(t *testing.T) {
	c := collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{svc("app", "/opt/data:/opt/data")},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "identity_mount" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected identity_mount finding")
	}
}

func TestAnonymousNoPersistence(t *testing.T) {
	c := collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{svc("app", "/data")},
	})
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "anonymous_no_persistence" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected anonymous_no_persistence finding")
	}
}

func TestSeverityOrdering(t *testing.T) {
	c := collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			svc("app", "/data", "/var/run/docker.sock:/var/run/docker.sock", "/opt/data:/opt/data"),
			svc("worker", "data:/data"),
		},
	})
	r := Analyze(c)
	if len(r.Findings) == 0 {
		t.Fatal("expected findings")
	}
	for i := 1; i < len(r.Findings); i++ {
		if sevOrder(r.Findings[i].Severity) < sevOrder(r.Findings[i-1].Severity) {
			t.Fatalf("findings not ordered by severity: %s before %s",
				r.Findings[i-1].Severity, r.Findings[i].Severity)
		}
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	text := FormatText(r)
	if !strings.Contains(text, "Volume Audit") {
		t.Fatal("expected header")
	}
	if !strings.Contains(text, "No volume mounts") {
		t.Fatal("expected no volumes message")
	}
}

func TestFormatTextWithData(t *testing.T) {
	c := collected(compose.File{
		Path: "docker-compose.yml",
		Services: []compose.Service{
			svc("app", "data:/data"),
			svc("worker", "data:/data"),
		},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Shared Volumes") {
		t.Fatal("expected shared volumes section")
	}
	if !strings.Contains(text, "Findings") {
		t.Fatal("expected findings section")
	}
}

func TestFormatJSON(t *testing.T) {
	c := collected(compose.File{
		Path:     "docker-compose.yml",
		Services: []compose.Service{svc("app", "data:/data")},
	})
	r := Analyze(c)
	j := FormatJSON(r)
	if !strings.Contains(j, `"volumes_scanned"`) {
		t.Fatal("expected volumes_scanned in JSON")
	}
}

func TestMultipleComposeFiles(t *testing.T) {
	c := collected(
		compose.File{
			Path:     "docker-compose.yml",
			Services: []compose.Service{svc("app", "shared:/data")},
		},
		compose.File{
			Path:     "docker-compose.override.yml",
			Services: []compose.Service{svc("worker", "shared:/data")},
		},
	)
	r := Analyze(c)
	if len(r.SharedVolumes) != 1 {
		t.Fatalf("expected 1 shared volume across files, got %d", len(r.SharedVolumes))
	}
	if len(r.SharedVolumes[0].Files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(r.SharedVolumes[0].Files))
	}
}
