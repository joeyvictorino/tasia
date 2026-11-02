package tmpdir

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

func TestSharedHostTmpMount(t *testing.T) {
	c := collected(compose.Service{
		Name:    "agent",
		Volumes: []string{"/tmp:/tmp"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "shared_tmp_mount") {
		t.Error("expected shared_tmp_mount for /tmp:/tmp")
	}
}

func TestSharedVarTmpMount(t *testing.T) {
	c := collected(compose.Service{
		Name:    "worker",
		Volumes: []string{"/var/tmp:/var/tmp"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "shared_tmp_mount") {
		t.Error("expected shared_tmp_mount for /var/tmp:/var/tmp")
	}
}

func TestTmpNoNoexecVolume(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"./data:/tmp"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "tmp_no_noexec") {
		t.Error("expected tmp_no_noexec for writable /tmp volume without noexec")
	}
}

func TestTmpWithNoexecSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"./data:/tmp:noexec"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "tmp_no_noexec") {
		t.Error("should not flag /tmp mount with noexec")
	}
}

func TestTmpReadonlySafe(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"./data:/tmp:ro"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "tmp_no_noexec") {
		t.Error("should not flag read-only /tmp mount")
	}
}

func TestInterserviceCommViaNamed(t *testing.T) {
	c := collected(
		compose.Service{
			Name:    "producer",
			Volumes: []string{"shared-tmp:/tmp"},
		},
		compose.Service{
			Name:    "consumer",
			Volumes: []string{"shared-tmp:/tmp"},
		},
	)
	r := Analyze(c)
	foundProducer := false
	foundConsumer := false
	for _, sr := range r.Services {
		if hasRule(sr, "tmp_interservice_comm") {
			if sr.Service == "producer" {
				foundProducer = true
			}
			if sr.Service == "consumer" {
				foundConsumer = true
			}
		}
	}
	if !foundProducer || !foundConsumer {
		t.Error("expected tmp_interservice_comm for both producer and consumer")
	}
}

func TestSingleNamedVolumeNoComm(t *testing.T) {
	c := collected(compose.Service{
		Name:    "solo",
		Volumes: []string{"my-tmp:/tmp"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "tmp_interservice_comm") {
		t.Error("should not flag single-service named volume as inter-service comm")
	}
}

func TestTmpfsNoNoexec(t *testing.T) {
	c := collected(compose.Service{
		Name:  "worker",
		Tmpfs: []string{"/tmp"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "tmp_no_noexec") {
		t.Error("expected tmp_no_noexec for tmpfs /tmp without noexec")
	}
}

func TestTmpfsWithNoexec(t *testing.T) {
	c := collected(compose.Service{
		Name:  "worker",
		Tmpfs: []string{"/tmp:noexec,nosuid"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "tmp_no_noexec") {
		t.Error("should not flag tmpfs /tmp with noexec")
	}
}

func TestNonTmpPathIgnored(t *testing.T) {
	c := collected(compose.Service{
		Name:    "app",
		Volumes: []string{"./data:/data"},
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected no findings for non-tmp path, got %d", len(r.Services[0].Findings))
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{Name: "clean"})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for clean service, got %d", len(r.Services[0].Findings))
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestSummaryCountsCorrect(t *testing.T) {
	c := collected(
		compose.Service{Name: "a", Volumes: []string{"/tmp:/tmp"}},
		compose.Service{Name: "b", Tmpfs: []string{"/var/tmp"}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.SharedTmpMounts < 1 {
		t.Error("expected at least 1 shared tmp mount")
	}
	if r.Summary.NoExecViolations < 1 {
		t.Error("expected at least 1 noexec violation")
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{Name: "web", Volumes: []string{"/tmp:/tmp"}})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !containsStr(text, "Temp Directory") {
		t.Error("expected header in text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "web", Volumes: []string{"/tmp:/tmp"}})
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

func TestDevShmMount(t *testing.T) {
	c := collected(compose.Service{
		Name:    "gpu",
		Volumes: []string{"/dev/shm:/dev/shm"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "shared_tmp_mount") {
		t.Error("expected shared_tmp_mount for /dev/shm host mount")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
