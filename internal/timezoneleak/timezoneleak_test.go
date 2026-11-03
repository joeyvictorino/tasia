package timezoneleak

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	cf := compose.File{Path: "docker-compose.yml", Services: services}
	return &collect.Collected{Root: "/test", ComposeFiles: []compose.File{cf}}
}

func TestNoTimezoneLeaks(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"PORT=8080"}})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestTzEnvSet(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"TZ=America/New_York"}})
	r := Analyze(c)
	if r.Summary.TzEnvSet == 0 {
		t.Error("expected timezoneleak_tz_env_set finding")
	}
}

func TestTzUtcNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"TZ=UTC"}})
	r := Analyze(c)
	if r.Summary.TzEnvSet != 0 {
		t.Error("UTC timezone should not be flagged")
	}
}

func TestTzEtcUtcNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"TZ=Etc/UTC"}})
	r := Analyze(c)
	if r.Summary.TzEnvSet != 0 {
		t.Error("Etc/UTC timezone should not be flagged")
	}
}

func TestLocaleEnvSet(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"LANG=en_US.UTF-8"}})
	r := Analyze(c)
	if r.Summary.LocaleEnvSet == 0 {
		t.Error("expected timezoneleak_locale_env_set finding")
	}
}

func TestLocaleCNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"LANG=C"}})
	r := Analyze(c)
	if r.Summary.LocaleEnvSet != 0 {
		t.Error("C locale should not be flagged")
	}
}

func TestLocalePosixNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"LC_ALL=POSIX"}})
	r := Analyze(c)
	if r.Summary.LocaleEnvSet != 0 {
		t.Error("POSIX locale should not be flagged")
	}
}

func TestTimezoneMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Volumes: []string{"/etc/localtime:/etc/localtime:ro"},
	})
	r := Analyze(c)
	if r.Summary.TimezoneMount == 0 {
		t.Error("expected timezoneleak_timezone_mount finding")
	}
}

func TestTimezoneFileMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Volumes: []string{"/etc/timezone:/etc/timezone:ro"},
	})
	r := Analyze(c)
	if r.Summary.TimezoneMount == 0 {
		t.Error("expected timezoneleak_timezone_mount finding for /etc/timezone")
	}
}

func TestTzLabelExposed(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:   "web",
		Labels: map[string]string{"app.timezone": "US/Eastern"},
	})
	r := Analyze(c)
	if r.Summary.TzLabelExposed == 0 {
		t.Error("expected timezoneleak_tz_label_exposed finding")
	}
}

func TestInconsistentTz(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "svc1", Environment: []string{"TZ=America/New_York"}},
		compose.Service{Name: "svc2", Environment: []string{"TZ=Europe/London"}},
	)
	r := Analyze(c)
	if r.Summary.InconsistentTz == 0 {
		t.Error("expected timezoneleak_inconsistent_tz finding for mismatched timezones")
	}
}

func TestConsistentTzNotFlagged(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "svc1", Environment: []string{"TZ=America/New_York"}},
		compose.Service{Name: "svc2", Environment: []string{"TZ=America/New_York"}},
	)
	r := Analyze(c)
	if r.Summary.InconsistentTz != 0 {
		t.Error("consistent timezones should not trigger inconsistency finding")
	}
}

func TestTzMountHostNetwork(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "web",
		Volumes:     []string{"/etc/localtime:/etc/localtime:ro"},
		NetworkMode: "host",
	})
	r := Analyze(c)
	if r.Summary.TzMountHostNetwork == 0 {
		t.Error("expected timezoneleak_tz_mount_host_network finding")
	}
}

func TestTzMountNoHostNetworkOk(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Volumes: []string{"/etc/localtime:/etc/localtime:ro"},
	})
	r := Analyze(c)
	if r.Summary.TzMountHostNetwork != 0 {
		t.Error("tz mount without host network should not trigger host network finding")
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "a", Environment: []string{"TZ=Asia/Tokyo"}},
		compose.Service{Name: "b"},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"TZ=Europe/Berlin"}})
	r := Analyze(c)
	text := FormatText(r)
	if !containsStr(text, "Timezone") {
		t.Error("expected 'Timezone' in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	text := FormatText(r)
	if !containsStr(text, "no findings") {
		t.Error("expected 'no findings' in output")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestLcCtypeLocale(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Environment: []string{"LC_CTYPE=ja_JP.UTF-8"}})
	r := Analyze(c)
	if r.Summary.LocaleEnvSet == 0 {
		t.Error("expected locale finding for LC_CTYPE")
	}
}

func TestReportPath(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
	r := Analyze(c)
	if r.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.Path)
	}
}

func containsStr(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && contains(s, substr)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
