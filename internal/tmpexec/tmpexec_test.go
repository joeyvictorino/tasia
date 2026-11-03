package tmpexec

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

func TestHostTmpMount(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/tmp:/tmp"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "tmp_host_mount") {
		t.Error("expected tmp_host_mount for /tmp:/tmp volume")
	}
	if r.Summary.HostTmpMount != 1 {
		t.Errorf("expected 1 host_tmp_mount, got %d", r.Summary.HostTmpMount)
	}
}

func TestHostTmpSubdir(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/tmp/data:/data"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "tmp_host_mount") {
		t.Error("expected tmp_host_mount for /tmp/data mount")
	}
}

func TestNoHostTmpMount(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/data:/data"}})
	r := Analyze(c)
	if hasRule(r.Services[0], "tmp_host_mount") {
		t.Error("should not flag non-tmp volumes")
	}
}

func TestTmpfsExecMount(t *testing.T) {
	c := collected(compose.Service{Name: "app", Tmpfs: []string{"/tmp"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "tmp_exec_mount") {
		t.Error("expected tmp_exec_mount for tmpfs /tmp without noexec")
	}
	if r.Summary.TmpExecMounts != 1 {
		t.Errorf("expected 1 tmp_exec_mount, got %d", r.Summary.TmpExecMounts)
	}
}

func TestTmpfsWithNoexec(t *testing.T) {
	c := collected(compose.Service{Name: "app", Tmpfs: []string{"/tmp:noexec,size=64m"}})
	r := Analyze(c)
	if hasRule(r.Services[0], "tmp_exec_mount") {
		t.Error("should not flag tmpfs with noexec")
	}
}

func TestLargeTmpfs(t *testing.T) {
	c := collected(compose.Service{Name: "app", Tmpfs: []string{"/tmp:size=2g"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "tmp_large_tmpfs") {
		t.Error("expected tmp_large_tmpfs for 2g tmpfs")
	}
	if r.Summary.LargeTmpfs != 1 {
		t.Errorf("expected 1 large_tmpfs, got %d", r.Summary.LargeTmpfs)
	}
}

func TestSmallTmpfs(t *testing.T) {
	c := collected(compose.Service{Name: "app", Tmpfs: []string{"/tmp:size=64m"}})
	r := Analyze(c)
	if hasRule(r.Services[0], "tmp_large_tmpfs") {
		t.Error("should not flag small tmpfs")
	}
}

func TestBoundaryTmpfs(t *testing.T) {
	c := collected(compose.Service{Name: "app", Tmpfs: []string{"/tmp:size=1g"}})
	r := Analyze(c)
	if hasRule(r.Services[0], "tmp_large_tmpfs") {
		t.Error("1g boundary should not be flagged")
	}
}

func TestNoTmpIsolation(t *testing.T) {
	c := collected(compose.Service{Name: "web"})
	r := Analyze(c)
	if !hasRule(r.Services[0], "tmp_no_isolation") {
		t.Error("expected tmp_no_isolation when no tmp settings and not read-only")
	}
	if r.Summary.NoTmpIsolation != 1 {
		t.Errorf("expected 1 no_tmp_isolation, got %d", r.Summary.NoTmpIsolation)
	}
}

func TestReadOnlyNoIsolation(t *testing.T) {
	c := collected(compose.Service{Name: "web", ReadOnly: true})
	r := Analyze(c)
	if hasRule(r.Services[0], "tmp_no_isolation") {
		t.Error("should not flag read-only filesystem")
	}
}

func TestTmpfsNoIsolation(t *testing.T) {
	c := collected(compose.Service{Name: "web", Tmpfs: []string{"/run"}})
	r := Analyze(c)
	if hasRule(r.Services[0], "tmp_no_isolation") {
		t.Error("should not flag when tmpfs is configured")
	}
}

func TestPrivilegedTmpVolume(t *testing.T) {
	c := collected(compose.Service{Name: "agent", Privileged: true, Volumes: []string{"/tmp:/tmp"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "tmp_privileged_access") {
		t.Error("expected tmp_privileged_access for privileged + /tmp volume")
	}
	if r.Summary.PrivilegedTmpAccess != 1 {
		t.Errorf("expected 1 privileged_tmp_access, got %d", r.Summary.PrivilegedTmpAccess)
	}
}

func TestPrivilegedTmpfs(t *testing.T) {
	c := collected(compose.Service{Name: "agent", Privileged: true, Tmpfs: []string{"/tmp"}})
	r := Analyze(c)
	if !hasRule(r.Services[0], "tmp_privileged_access") {
		t.Error("expected tmp_privileged_access for privileged + tmpfs /tmp")
	}
}

func TestPrivilegedNoTmp(t *testing.T) {
	c := collected(compose.Service{Name: "agent", Privileged: true})
	r := Analyze(c)
	if hasRule(r.Services[0], "tmp_privileged_access") {
		t.Error("should not flag privileged without /tmp access")
	}
}

func TestMultipleServices(t *testing.T) {
	c := collected(
		compose.Service{Name: "web", ReadOnly: true},
		compose.Service{Name: "app", Tmpfs: []string{"/tmp"}},
		compose.Service{Name: "db"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
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
	c := collected(compose.Service{Name: "web", Tmpfs: []string{"/tmp"}})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{Name: "app", Volumes: []string{"/tmp:/tmp"}})
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
