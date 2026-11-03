package cronaudit

import (
	"encoding/json"
	"strings"
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

func TestCronImageDetected(t *testing.T) {
	c := collected(compose.Service{
		Name:  "scheduler",
		Image: "supercronic:latest",
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cronaudit_cron_in_container") {
		t.Error("expected cronaudit_cron_in_container for cron image")
	}
	if r.Summary.CronInContainers < 1 {
		t.Errorf("expected cron in containers >= 1, got %d", r.Summary.CronInContainers)
	}
}

func TestOfeliaImage(t *testing.T) {
	c := collected(compose.Service{
		Name:  "ofelia",
		Image: "mcuadros/ofelia:latest",
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cronaudit_cron_in_container") {
		t.Error("expected cronaudit_cron_in_container for ofelia image")
	}
}

func TestCronEnvSchedule(t *testing.T) {
	c := collected(compose.Service{
		Name:        "worker",
		Image:       "python:3.11",
		Environment: []string{"CRON_SCHEDULE=*/5 * * * *"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cronaudit_cron_in_container") {
		t.Error("expected cronaudit_cron_in_container for CRON_SCHEDULE env")
	}
}

func TestWritableCrontabMount(t *testing.T) {
	c := collected(compose.Service{
		Name:    "cron-svc",
		Image:   "cron:latest",
		Volumes: []string{"./crontabs:/etc/cron.d"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cronaudit_writable_crontab") {
		t.Error("expected cronaudit_writable_crontab for writable cron mount")
	}
	if r.Summary.WritableCrontabs < 1 {
		t.Errorf("expected writable crontabs >= 1, got %d", r.Summary.WritableCrontabs)
	}
}

func TestReadOnlyCrontabMount(t *testing.T) {
	c := collected(compose.Service{
		Name:    "cron-svc",
		Image:   "cron:latest",
		Volumes: []string{"./crontabs:/etc/cron.d:ro"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "cronaudit_writable_crontab") {
		t.Error("should not flag read-only crontab mount as writable")
	}
	if !hasRule(r.Services[0], "cronaudit_crontab_mount") {
		t.Error("expected cronaudit_crontab_mount for read-only cron mount")
	}
}

func TestPrivilegedCron(t *testing.T) {
	c := collected(compose.Service{
		Name:       "root-cron",
		Image:      "cron:latest",
		Privileged: true,
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cronaudit_privileged_cron") {
		t.Error("expected cronaudit_privileged_cron for privileged cron container")
	}
	if r.Summary.PrivilegedScheduled < 1 {
		t.Errorf("expected privileged scheduled >= 1, got %d", r.Summary.PrivilegedScheduled)
	}
}

func TestNoCronLogging(t *testing.T) {
	c := collected(compose.Service{
		Name:  "quiet-cron",
		Image: "cron:latest",
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cronaudit_no_logging") {
		t.Error("expected cronaudit_no_logging for cron without logging")
	}
	if r.Summary.MissingCronLogging < 1 {
		t.Errorf("expected missing cron logging >= 1, got %d", r.Summary.MissingCronLogging)
	}
}

func TestCronWithLogging(t *testing.T) {
	c := collected(compose.Service{
		Name:        "logged-cron",
		Image:       "cron:latest",
		Environment: []string{"CRON_LOG_LEVEL=info"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "cronaudit_no_logging") {
		t.Error("should not flag cron with logging configured")
	}
}

func TestRootCronJob(t *testing.T) {
	c := collected(compose.Service{
		Name:        "root-task",
		Image:       "python:3.11",
		Environment: []string{"CRON_USER=root"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cronaudit_root_cron") {
		t.Error("expected cronaudit_root_cron for CRON_USER=root")
	}
	if r.Summary.RootCronJobs < 1 {
		t.Errorf("expected root cron jobs >= 1, got %d", r.Summary.RootCronJobs)
	}
}

func TestSudoCronJob(t *testing.T) {
	c := collected(compose.Service{
		Name:        "sudo-task",
		Image:       "python:3.11",
		Environment: []string{"CRON_CMD=sudo /usr/bin/cleanup"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cronaudit_root_cron") {
		t.Error("expected cronaudit_root_cron for CRON_CMD with sudo")
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{
		Name:  "web",
		Image: "nginx:latest",
	})
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

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name:  "cron",
		Image: "cron:latest",
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
	if !strings.Contains(text, "Cron Job") {
		t.Error("expected 'Cron Job' in format output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name:  "svc",
		Image: "supercronic:latest",
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

func TestVarSpoolCronMount(t *testing.T) {
	c := collected(compose.Service{
		Name:    "spool-cron",
		Image:   "alpine:latest",
		Volumes: []string{"cron-data:/var/spool/cron"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "cronaudit_writable_crontab") {
		t.Error("expected cronaudit_writable_crontab for /var/spool/cron mount")
	}
}
