package noexec

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

func hasRule(sr ServiceResult, rule string) bool {
	for _, f := range sr.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestTmpfsWithoutNoexec(t *testing.T) {
	c := collected(compose.Service{Name: "web", Tmpfs: []string{"/tmp"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "noexec_tmpfs_missing") {
		t.Error("expected noexec_tmpfs_missing for tmpfs /tmp without noexec")
	}
}

func TestTmpfsWithNoexec(t *testing.T) {
	c := collected(compose.Service{Name: "web", Tmpfs: []string{"/tmp:noexec,nosuid"}})
	r := Analyze(c)
	if hasRule(r.Services[0], "noexec_tmpfs_missing") {
		t.Error("should not flag tmpfs with noexec option")
	}
}

func TestDevMountWithoutNoexec(t *testing.T) {
	c := collected(compose.Service{
		Name:    "worker",
		Volumes: []string{"/dev:/dev"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "noexec_dev_missing") {
		t.Error("expected noexec_dev_missing for /dev mount without noexec")
	}
}

func TestDevMountWithNoexec(t *testing.T) {
	c := collected(compose.Service{
		Name:    "worker",
		Volumes: []string{"/dev:/dev:noexec"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "noexec_dev_missing") {
		t.Error("should not flag /dev with noexec")
	}
}

func TestTmpMountWithoutNoexec(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"./tmp:/tmp"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "noexec_tmp_writable") {
		t.Error("expected noexec_tmp_writable for /tmp mount")
	}
}

func TestRunMountWithoutNoexec(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/run:/run"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "noexec_run_missing") {
		t.Error("expected noexec_run_missing for /run mount")
	}
}

func TestHomeMountWithoutNoexec(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/home/user:/home/user"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "noexec_home_writable") {
		t.Error("expected noexec_home_writable for /home mount")
	}
}

func TestWritableVolumeAtSensitivePath(t *testing.T) {
	c := collected(compose.Service{
		Name:    "deploy",
		Volumes: []string{"/opt/app:/opt/app"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "noexec_writable_volume") {
		t.Error("expected noexec_writable_volume for writable /opt mount")
	}
}

func TestReadonlyVolumeSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:    "reader",
		Volumes: []string{"/opt/app:/opt/app:ro"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "noexec_writable_volume") {
		t.Error("should not flag read-only volume")
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{Name: "clean"})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for clean service, got %d", len(r.Services[0].Findings))
	}
}

func TestSummary(t *testing.T) {
	c := collected(
		compose.Service{Name: "web", Tmpfs: []string{"/tmp"}},
		compose.Service{Name: "db", Volumes: []string{"/data:/data"}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.WithTmpfs != 1 {
		t.Errorf("expected 1 with tmpfs, got %d", r.Summary.WithTmpfs)
	}
	if r.Summary.WithVolumes != 1 {
		t.Errorf("expected 1 with volumes, got %d", r.Summary.WithVolumes)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{Name: "web", Tmpfs: []string{"/tmp"}})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !contains(text, "No-Exec Mount Audit") {
		t.Error("expected header in text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "web", Tmpfs: []string{"/tmp"}})
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

func TestEmptyCollected(t *testing.T) {
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
