package timesync

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

func TestNoTimezoneSet(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "worker",
	})
	r := Analyze(c)
	if !findRule(r.Services, "time_no_timezone") {
		t.Error("expected time_no_timezone when TZ is not set")
	}
}

func TestTimezoneSetUTC(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"TZ=UTC"},
	})
	r := Analyze(c)
	if findRule(r.Services, "time_no_timezone") {
		t.Error("should not flag when TZ is set")
	}
}

func TestUtcNotEnforcedEastern(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"TZ=America/New_York"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "time_utc_not_enforced") {
		t.Error("expected time_utc_not_enforced for America/New_York")
	}
}

func TestUtcNotEnforcedEurope(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"TZ=Europe/London"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "time_utc_not_enforced") {
		t.Error("expected time_utc_not_enforced for Europe/London")
	}
}

func TestUtcEnforcedUTC(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"TZ=UTC"},
	})
	r := Analyze(c)
	if findRule(r.Services, "time_utc_not_enforced") {
		t.Error("should not flag TZ=UTC")
	}
}

func TestUtcEnforcedEtcUTC(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"TZ=Etc/UTC"},
	})
	r := Analyze(c)
	if findRule(r.Services, "time_utc_not_enforced") {
		t.Error("should not flag TZ=Etc/UTC")
	}
}

func TestUtcEnforcedGMT(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "app",
		Environment: []string{"TZ=GMT"},
	})
	r := Analyze(c)
	if findRule(r.Services, "time_utc_not_enforced") {
		t.Error("should not flag TZ=GMT")
	}
}

func TestNtpDisabledFalse(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"NTP_ENABLED=false"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "time_ntp_disabled") {
		t.Error("expected time_ntp_disabled for NTP_ENABLED=false")
	}
}

func TestNtpDisabledZero(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"ENABLE_NTP=0"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "time_ntp_disabled") {
		t.Error("expected time_ntp_disabled for ENABLE_NTP=0")
	}
}

func TestNtpEnabled(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "worker",
		Environment: []string{"NTP_ENABLED=true"},
	})
	r := Analyze(c)
	if findRule(r.Services, "time_ntp_disabled") {
		t.Error("should not flag NTP_ENABLED=true")
	}
}

func TestHostTimeMountedLocaltime(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"/etc/localtime:/etc/localtime:ro"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "time_host_mounted") {
		t.Error("expected time_host_mounted for /etc/localtime mount")
	}
}

func TestHostTimeMountedTimezone(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"/etc/timezone:/etc/timezone:ro"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "time_host_mounted") {
		t.Error("expected time_host_mounted for /etc/timezone mount")
	}
}

func TestNoHostTimeMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"/data:/app/data"},
	})
	r := Analyze(c)
	if findRule(r.Services, "time_host_mounted") {
		t.Error("should not flag non-time volume mount")
	}
}

func TestPrivilegedTimeDrift(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "infra",
		Privileged:  true,
		Environment: []string{"NTP_ENABLED=false"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "time_privileged_drift") {
		t.Error("expected time_privileged_drift for privileged + NTP disabled")
	}
}

func TestPrivilegedNoTimezone(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "infra",
		Privileged: true,
	})
	r := Analyze(c)
	if !findRule(r.Services, "time_privileged_drift") {
		t.Error("expected time_privileged_drift for privileged + no timezone")
	}
}

func TestPrivilegedWithUTC(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "infra",
		Privileged:  true,
		Environment: []string{"TZ=UTC"},
	})
	r := Analyze(c)
	if findRule(r.Services, "time_privileged_drift") {
		t.Error("should not flag privileged with proper TZ and no NTP issues")
	}
}

func TestNoFindingsWithUTC(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "web",
		Environment: []string{"TZ=UTC"},
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
		compose.Service{Name: "web", Environment: []string{"TZ=UTC"}},
		compose.Service{Name: "worker"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "broken",
		Privileged:  true,
		Environment: []string{"NTP_ENABLED=false"},
		Volumes:     []string{"/etc/localtime:/etc/localtime:ro"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{Name: "worker"})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Time Sync") {
		t.Error("expected 'Time Sync' in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"TZ=UTC"}})
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
