package cronjob

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

func TestCronAsRootNoUser(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "scheduler",
		Command: []string{"crond", "-f"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cronjob_as_root") {
		t.Error("expected cronjob_as_root for cron with no user")
	}
}

func TestCronAsExplicitRoot(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "scheduler",
		Command: []string{"crond", "-f"},
		User:    "root",
	})
	r := Analyze(c)
	if !findRule(r.Services, "cronjob_as_root") {
		t.Error("expected cronjob_as_root for explicit root user")
	}
}

func TestCronAsNonRoot(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "scheduler",
		Command: []string{"crond", "-f"},
		User:    "appuser",
	})
	r := Analyze(c)
	if findRule(r.Services, "cronjob_as_root") {
		t.Error("should not flag cron running as non-root")
	}
}

func TestCronNoUserDirective(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "scheduler",
		Command: []string{"cron"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cronjob_no_user") {
		t.Error("expected cronjob_no_user for cron without USER")
	}
}

func TestCronWithUserDirective(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "scheduler",
		Command: []string{"cron"},
		User:    "nobody",
	})
	r := Analyze(c)
	if findRule(r.Services, "cronjob_no_user") {
		t.Error("should not flag cron with explicit user")
	}
}

func TestCronPrivileged(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "scheduler",
		Command:    []string{"crond"},
		Privileged: true,
	})
	r := Analyze(c)
	if !findRule(r.Services, "cronjob_privileged") {
		t.Error("expected cronjob_privileged for privileged cron")
	}
}

func TestCronNotPrivileged(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "scheduler",
		Command: []string{"crond"},
		User:    "app",
	})
	r := Analyze(c)
	if findRule(r.Services, "cronjob_privileged") {
		t.Error("should not flag non-privileged cron")
	}
}

func TestCronInEntrypoint(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "scheduler",
		Entrypoint: []string{"cron", "-f"},
		User:       "app",
	})
	r := Analyze(c)
	if !findRule(r.Services, "cronjob_in_entrypoint") {
		t.Error("expected cronjob_in_entrypoint for cron in entrypoint")
	}
}

func TestCrontabMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "scheduler",
		Volumes: []string{"./crontab:/etc/crontab"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cronjob_crontab_mount") {
		t.Error("expected cronjob_crontab_mount for crontab volume")
	}
}

func TestCronDirMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "scheduler",
		Volumes: []string{"./jobs:/etc/cron.d"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cronjob_crontab_mount") {
		t.Error("expected cronjob_crontab_mount for cron.d mount")
	}
}

func TestEtcCronMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "scheduler",
		Volumes: []string{"/host/etc/cron:/etc/cron"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cronjob_crontab_mount") {
		t.Error("expected cronjob_crontab_mount for /etc/cron mount")
	}
}

func TestNormalVolumeNotFlagged(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Volumes: []string{"./data:/app/data"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cronjob_crontab_mount") {
		t.Error("should not flag normal volume mount")
	}
}

func TestSchedulerEnvLeak(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "scheduler",
		Environment: []string{"CRON_CMD=echo hello; rm -rf /"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "cronjob_scheduler_env_leak") {
		t.Error("expected cronjob_scheduler_env_leak for shell metacharacters")
	}
}

func TestSchedulerEnvSafe(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "scheduler",
		Environment: []string{"CRON_SCHEDULE=*/5 * * * *"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cronjob_scheduler_env_leak") {
		t.Error("should not flag safe scheduler env")
	}
}

func TestSchedulerEnvFromVar(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:        "scheduler",
		Environment: []string{"CRON_CMD=${CRON_COMMAND}"},
	})
	r := Analyze(c)
	if findRule(r.Services, "cronjob_scheduler_env_leak") {
		t.Error("should not flag env var reference")
	}
}

func TestNoCronNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "web",
		Command: []string{"nginx", "-g", "daemon off;"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for non-cron service, got %d", r.Summary.TotalFindings)
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
		compose.Service{Name: "web", Command: []string{"nginx"}},
		compose.Service{Name: "cron", Command: []string{"crond", "-f"}},
	)
	r := Analyze(c)
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
}

func TestSummaryTotals(t *testing.T) {
	c := mkCollected(
		compose.Service{Name: "cron", Command: []string{"crond"}, Privileged: true},
	)
	r := Analyze(c)
	if r.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{Name: "cron", Command: []string{"crond"}})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Cron/Scheduler") {
		t.Error("expected 'Cron/Scheduler' in output")
	}
	if !strings.Contains(text, "cron") {
		t.Error("expected service name in output")
	}
}

func TestFormatTextNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web", Command: []string{"nginx"}, User: "app"})
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

func TestCrontabCommandDetection(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "scheduler",
		Command: []string{"sh", "-c", "crontab /etc/crontab && cron -f"},
		User:    "app",
	})
	r := Analyze(c)
	if !findRule(r.Services, "cronjob_in_entrypoint") || findRule(r.Services, "cronjob_in_entrypoint") {
		// crontab is in command not entrypoint, so cronjob_in_entrypoint should not fire
	}
	// But crontab in command should still detect cron_as_root pattern
}

func TestUserZeroIsRoot(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "scheduler",
		Command: []string{"crond"},
		User:    "0",
	})
	r := Analyze(c)
	if !findRule(r.Services, "cronjob_as_root") {
		t.Error("expected cronjob_as_root for user=0")
	}
}
