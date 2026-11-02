package volumes

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeDockerSockMount(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:    "dind",
				Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
			}},
		}},
	}
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "sensitive_mount" && f.Severity == "critical" {
			found = true
		}
	}
	if !found {
		t.Error("expected critical finding for docker.sock mount")
	}
}

func TestAnalyzeProcMount(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:    "monitor",
				Volumes: []string{"/proc:/host/proc:ro"},
			}},
		}},
	}
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "sensitive_mount" {
			found = true
		}
	}
	if !found {
		t.Error("expected sensitive_mount finding for /proc mount")
	}
	if r.Mounts[0].ReadOnly != true {
		t.Error("expected read-only mount for :ro suffix")
	}
}

func TestAnalyzeWritableHostMount(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:    "app",
				Volumes: []string{"/etc/config:/config"},
			}},
		}},
	}
	r := Analyze(c)
	hasWritable := false
	for _, f := range r.Findings {
		if f.Category == "writable_host_mount" {
			hasWritable = true
		}
	}
	if !hasWritable {
		t.Error("expected writable_host_mount finding for writable /etc mount")
	}
}

func TestAnalyzeNamedVolume(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:    "db",
				Volumes: []string{"pgdata:/var/lib/postgresql/data"},
			}},
		}},
	}
	r := Analyze(c)
	if len(r.Findings) != 0 {
		t.Errorf("expected no findings for named volume, got %d", len(r.Findings))
	}
	if r.Summary.NamedVolumes != 1 {
		t.Errorf("expected 1 named volume, got %d", r.Summary.NamedVolumes)
	}
}

func TestAnalyzeAnonymousVolume(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:    "cache",
				Volumes: []string{"/tmp/cache"},
			}},
		}},
	}
	r := Analyze(c)
	hasAnon := false
	for _, f := range r.Findings {
		if f.Category == "anonymous_volume" {
			hasAnon = true
		}
	}
	if !hasAnon {
		t.Error("expected anonymous_volume finding")
	}
	if r.Summary.AnonymousMounts != 1 {
		t.Errorf("expected 1 anonymous mount, got %d", r.Summary.AnonymousMounts)
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalMounts != 0 {
		t.Errorf("expected 0 mounts, got %d", r.Summary.TotalMounts)
	}
}

func TestAnalyzeMultipleServices(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{
					Name:    "web",
					Volumes: []string{"static:/app/static", "/var/run/docker.sock:/var/run/docker.sock"},
				},
				{
					Name:    "db",
					Volumes: []string{"pgdata:/var/lib/postgresql/data"},
				},
			},
		}},
	}
	r := Analyze(c)
	if r.Summary.TotalMounts != 3 {
		t.Errorf("expected 3 mounts, got %d", r.Summary.TotalMounts)
	}
	if r.Summary.HostBindMounts != 1 {
		t.Errorf("expected 1 bind mount, got %d", r.Summary.HostBindMounts)
	}
	if r.Summary.NamedVolumes != 2 {
		t.Errorf("expected 2 named volumes, got %d", r.Summary.NamedVolumes)
	}
}

func TestParseMountSpec(t *testing.T) {
	tests := []struct {
		spec     string
		wantType string
		wantRO   bool
		wantSrc  string
		wantTgt  string
	}{
		{"pgdata:/var/lib/postgresql/data", "named", false, "pgdata", "/var/lib/postgresql/data"},
		{"/host/path:/container/path", "bind", false, "/host/path", "/container/path"},
		{"/host/path:/container/path:ro", "bind", true, "/host/path", "/container/path"},
		{"./local:/app", "bind", false, "./local", "/app"},
		{"/tmp/data", "anonymous", false, "", "/tmp/data"},
		{"namedvol:/data:ro", "named", true, "namedvol", "/data"},
	}
	for _, tt := range tests {
		mi := parseMountSpec(tt.spec, "test", "test.yml")
		if mi.Type != tt.wantType {
			t.Errorf("parseMountSpec(%q).Type = %s, want %s", tt.spec, mi.Type, tt.wantType)
		}
		if mi.ReadOnly != tt.wantRO {
			t.Errorf("parseMountSpec(%q).ReadOnly = %v, want %v", tt.spec, mi.ReadOnly, tt.wantRO)
		}
		if mi.Source != tt.wantSrc {
			t.Errorf("parseMountSpec(%q).Source = %s, want %s", tt.spec, mi.Source, tt.wantSrc)
		}
		if mi.Target != tt.wantTgt {
			t.Errorf("parseMountSpec(%q).Target = %s, want %s", tt.spec, mi.Target, tt.wantTgt)
		}
	}
}

func TestFormatText(t *testing.T) {
	r := Report{
		Mounts: []MountInfo{{
			Service: "web", File: "docker-compose.yml",
			Source: "/host", Target: "/app", Type: "bind",
		}},
		Findings: []MountFinding{{
			Service: "web", File: "docker-compose.yml",
			Volume: "/host:/app", Category: "writable_host_mount",
			Severity: "medium", Detail: "test",
		}},
		Summary: Summary{TotalMounts: 1, Findings: 1, HostBindMounts: 1, WritableMounts: 1},
	}
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestReadOnlyMountSummary(t *testing.T) {
	c := &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{{
				Name:    "app",
				Volumes: []string{"/host/config:/config:ro", "data:/data"},
			}},
		}},
	}
	r := Analyze(c)
	if r.Summary.ReadOnlyMounts != 1 {
		t.Errorf("expected 1 read-only mount, got %d", r.Summary.ReadOnlyMounts)
	}
	if r.Summary.WritableMounts != 1 {
		t.Errorf("expected 1 writable mount, got %d", r.Summary.WritableMounts)
	}
}
