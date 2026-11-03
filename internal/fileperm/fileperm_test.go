package fileperm

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

func collectedWithDockerfile(content string) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		Dockerfiles: []collect.Dockerfile{
			{Path: "Dockerfile", Content: content},
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

func TestSensitivePathEtcShadow(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/etc/shadow:/secrets/shadow:ro"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "fileperm_sensitive_path_mount") {
		t.Error("expected fileperm_sensitive_path_mount for /etc/shadow mount")
	}
}

func TestSensitivePathSSH(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/root/.ssh:/app/.ssh"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "fileperm_sensitive_path_mount") {
		t.Error("expected fileperm_sensitive_path_mount for /root/.ssh mount")
	}
}

func TestSensitivePathDockerSock(t *testing.T) {
	c := collected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "fileperm_sensitive_path_mount") {
		t.Error("expected fileperm_sensitive_path_mount for docker.sock mount")
	}
}

func TestSensitivePathProc(t *testing.T) {
	c := collected(compose.Service{
		Name:    "monitor",
		Volumes: []string{"/proc:/host/proc:ro"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "fileperm_sensitive_path_mount") {
		t.Error("expected fileperm_sensitive_path_mount for /proc mount")
	}
}

func TestNormalVolumeSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"./data:/app/data"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "fileperm_sensitive_path_mount") {
		t.Error("should not flag normal data volume")
	}
}

func TestWorldWritableEtc(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/etc:/host-etc:rw"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "fileperm_world_writable_volume") {
		t.Error("expected fileperm_world_writable_volume for /etc mounted rw")
	}
}

func TestWorldWritableVarRun(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/var/run:/host-run"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "fileperm_world_writable_volume") {
		t.Error("expected fileperm_world_writable_volume for /var/run without :ro")
	}
}

func TestReadOnlyEtcSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/etc:/host-etc:ro"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "fileperm_world_writable_volume") {
		t.Error("should not flag /etc mounted read-only")
	}
}

func TestChmod777Detected(t *testing.T) {
	c := collectedWithDockerfile("FROM ubuntu\nRUN chmod 777 /app\n")
	r := Analyze(c)
	if !hasRule(r.Services[0], "fileperm_chmod_777") {
		t.Error("expected fileperm_chmod_777 for chmod 777")
	}
}

func TestChmod777Recursive(t *testing.T) {
	c := collectedWithDockerfile("FROM ubuntu\nRUN chmod -R 777 /var/data\n")
	r := Analyze(c)
	if !hasRule(r.Services[0], "fileperm_chmod_777") {
		t.Error("expected fileperm_chmod_777 for chmod -R 777")
	}
}

func TestChmod755Safe(t *testing.T) {
	c := collectedWithDockerfile("FROM ubuntu\nRUN chmod 755 /app\n")
	r := Analyze(c)
	if hasRule(r.Services[0], "fileperm_chmod_777") {
		t.Error("should not flag chmod 755")
	}
}

func TestNoDockerfileFindingsClean(t *testing.T) {
	c := collectedWithDockerfile("FROM python:3.11\nCOPY . /app\n")
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Services[0].Findings))
	}
}

func TestSummaryTotals(t *testing.T) {
	c := collected(
		compose.Service{Name: "a", Volumes: []string{"/etc/shadow:/s"}},
		compose.Service{Name: "b", Volumes: []string{"/etc:/e:rw"}},
	)
	r := Analyze(c)
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
	if r.Summary.SensitivePathMount < 1 {
		t.Error("expected at least 1 sensitive path mount")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/etc/shadow:/s"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"/etc/shadow:/s"},
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

func TestMultipleVolumeFindings(t *testing.T) {
	c := collected(compose.Service{
		Name: "risky",
		Volumes: []string{
			"/etc/shadow:/s",
			"/var/run/docker.sock:/docker.sock",
			"/etc:/host:rw",
		},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) < 3 {
		t.Errorf("expected at least 3 findings, got %d", len(r.Services[0].Findings))
	}
}

func TestCleanServiceNoFindings(t *testing.T) {
	c := collected(compose.Service{
		Name:  "clean",
		Image: "nginx:latest",
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Services[0].Findings))
	}
}
