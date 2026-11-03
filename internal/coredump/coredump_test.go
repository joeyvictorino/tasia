package coredump

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func findRule(results []ServiceResult, rule string) bool {
	for _, sr := range results {
		for _, f := range sr.Findings {
			if f.Rule == rule {
				return true
			}
		}
	}
	return false
}

func TestUnlimitedCoreSoft(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Ulimits: map[string]compose.UlimitValue{"core": {Soft: -1, Hard: 0}},
	})
	r := Analyze(c)
	if !findRule(r.Services, "coredump_unlimited") {
		t.Error("expected coredump_unlimited for soft=-1")
	}
}

func TestUnlimitedCoreHard(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Ulimits: map[string]compose.UlimitValue{"core": {Soft: 0, Hard: -1}},
	})
	r := Analyze(c)
	if !findRule(r.Services, "coredump_unlimited") {
		t.Error("expected coredump_unlimited for hard=-1")
	}
}

func TestLimitedCoreNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Ulimits: map[string]compose.UlimitValue{"core": {Soft: 1048576, Hard: 1048576}},
	})
	r := Analyze(c)
	if findRule(r.Services, "coredump_unlimited") {
		t.Error("should not flag limited core dumps")
	}
}

func TestSuidDumpableOne(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Sysctls: map[string]string{"fs.suid_dumpable": "1"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "coredump_suid_dumpable") {
		t.Error("expected coredump_suid_dumpable for fs.suid_dumpable=1")
	}
}

func TestSuidDumpableTwo(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Sysctls: map[string]string{"fs.suid_dumpable": "2"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "coredump_suid_dumpable") {
		t.Error("expected coredump_suid_dumpable for fs.suid_dumpable=2")
	}
}

func TestSuidDumpableZero(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Sysctls: map[string]string{"fs.suid_dumpable": "0"},
	})
	r := Analyze(c)
	if findRule(r.Services, "coredump_suid_dumpable") {
		t.Error("should not flag fs.suid_dumpable=0")
	}
}

func TestCorePathMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Volumes: []string{"./dumps:/var/crash"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "coredump_path_mount") {
		t.Error("expected coredump_path_mount for /var/crash volume")
	}
}

func TestCoredumpDirMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Volumes: []string{"/host/cores:/var/lib/systemd/coredump"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "coredump_path_mount") {
		t.Error("expected coredump_path_mount for systemd coredump path")
	}
}

func TestCoreInDestPath(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Volumes: []string{"./data:/app/core-dumps"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "coredump_path_mount") {
		t.Error("expected coredump_path_mount for core-dumps destination")
	}
}

func TestNormalVolumeNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Volumes: []string{"./data:/app/data"},
	})
	r := Analyze(c)
	if findRule(r.Services, "coredump_path_mount") {
		t.Error("should not flag normal volume mount")
	}
}

func TestCoreEnvExposed(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"CORE_DUMP_DIR=/tmp/cores"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "coredump_env_exposed") {
		t.Error("expected coredump_env_exposed for CORE_DUMP env var")
	}
}

func TestCorePatternEnv(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"CORE_PATTERN=/tmp/core.%p"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "coredump_env_exposed") {
		t.Error("expected coredump_env_exposed for CORE_PATTERN env var")
	}
}

func TestCoreEnvFromVar(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"CORE_DUMP_DIR=${DUMP_PATH}"},
	})
	r := Analyze(c)
	if findRule(r.Services, "coredump_env_exposed") {
		t.Error("should not flag env var reference")
	}
}

func TestCoreEnvNoKeyword(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"APP_MEM=512m"},
	})
	r := Analyze(c)
	if findRule(r.Services, "coredump_env_exposed") {
		t.Error("should not flag non-coredump env var")
	}
}

func TestPrivilegedUnlimitedCore(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "worker",
		Privileged: true,
		Ulimits:    map[string]compose.UlimitValue{"core": {Soft: -1, Hard: -1}},
	})
	r := Analyze(c)
	if !findRule(r.Services, "coredump_privileged") {
		t.Error("expected coredump_privileged for privileged + unlimited core")
	}
}

func TestPrivilegedLimitedCore(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "worker",
		Privileged: true,
		Ulimits:    map[string]compose.UlimitValue{"core": {Soft: 1024, Hard: 1024}},
	})
	r := Analyze(c)
	if findRule(r.Services, "coredump_privileged") {
		t.Error("should not flag privileged with limited core")
	}
}

func TestNoSeccompWithUnlimitedCore(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Ulimits: map[string]compose.UlimitValue{"core": {Soft: -1, Hard: -1}},
	})
	r := Analyze(c)
	if !findRule(r.Services, "coredump_no_seccomp") {
		t.Error("expected coredump_no_seccomp for unlimited core without seccomp")
	}
}

func TestSeccompWithUnlimitedCore(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Ulimits:     map[string]compose.UlimitValue{"core": {Soft: -1, Hard: -1}},
		SecurityOpt: []string{"seccomp=default.json"},
	})
	r := Analyze(c)
	if findRule(r.Services, "coredump_no_seccomp") {
		t.Error("should not flag when seccomp profile is set")
	}
}

func TestSeccompUnconfinedStillFlags(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Ulimits:     map[string]compose.UlimitValue{"core": {Soft: -1, Hard: -1}},
		SecurityOpt: []string{"seccomp=unconfined"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "coredump_no_seccomp") {
		t.Error("expected coredump_no_seccomp when seccomp=unconfined")
	}
}

func TestNoConfigNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "web",
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestMultipleServices(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "web"},
		compose.Service{Name: "worker", Ulimits: map[string]compose.UlimitValue{"core": {Soft: -1, Hard: -1}}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(
		compose.Service{
			Name:       "worker",
			Privileged: true,
			Ulimits:    map[string]compose.UlimitValue{"core": {Soft: -1, Hard: -1}},
		},
	)
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "worker",
		Ulimits: map[string]compose.UlimitValue{"core": {Soft: -1, Hard: -1}},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Core Dump") {
		t.Error("expected 'Core Dump' in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "no findings") {
		t.Error("expected 'no findings' in output")
	}
}

func TestReportPath(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.Path)
	}
}
