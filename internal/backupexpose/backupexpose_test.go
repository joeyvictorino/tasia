package backupexpose

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

func TestBackupMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "db",
		Volumes: []string{"./data:/backup/db"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_mount") {
		t.Error("expected backup_mount for /backup volume")
	}
}

func TestBackupMountBak(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./snapshots:/bak"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_mount") {
		t.Error("expected backup_mount for /bak volume")
	}
}

func TestNoBackupMount(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./src:/app/src"},
	})
	r := Analyze(c)
	if findRule(r.Services, "backup_mount") {
		t.Error("should not flag normal volume mount")
	}
}

func TestSQLDumpVolume(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "db",
		Volumes: []string{"./init.sql:/docker-entrypoint-initdb.d/init.sql"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_sql_dump") {
		t.Error("expected backup_sql_dump for .sql file mount")
	}
}

func TestSQLDumpGzVolume(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "db",
		Volumes: []string{"./backup.sql.gz:/data/backup.sql.gz"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_sql_dump") {
		t.Error("expected backup_sql_dump for .sql.gz file mount")
	}
}

func TestSQLDumpCommand(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "db",
		Command: []string{"sh", "-c", "mysqldump mydb > /backup/db.sql"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_sql_dump") {
		t.Error("expected backup_sql_dump for mysqldump in command")
	}
}

func TestPgDumpCommand(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:       "db",
		Entrypoint: []string{"sh", "-c", "pg_dump -U postgres mydb"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_sql_dump") {
		t.Error("expected backup_sql_dump for pg_dump in entrypoint")
	}
}

func TestNoSQLDump(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Command: []string{"python", "manage.py", "migrate"},
	})
	r := Analyze(c)
	if findRule(r.Services, "backup_sql_dump") {
		t.Error("should not flag command without SQL dump references")
	}
}

func TestArchiveExposeTar(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./release.tar.gz:/app/release.tar.gz"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_archive_expose") {
		t.Error("expected backup_archive_expose for .tar.gz mount")
	}
}

func TestArchiveExposeZip(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./data.zip:/data/archive.zip"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_archive_expose") {
		t.Error("expected backup_archive_expose for .zip mount")
	}
}

func TestNoArchiveExpose(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./config.yml:/app/config.yml"},
	})
	r := Analyze(c)
	if findRule(r.Services, "backup_archive_expose") {
		t.Error("should not flag non-archive file mount")
	}
}

func TestSwapFile(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./config.yml.swp:/app/.config.swp"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_swap_file") {
		t.Error("expected backup_swap_file for .swp file")
	}
}

func TestNoSwapFile(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./main.go:/app/main.go"},
	})
	r := Analyze(c)
	if findRule(r.Services, "backup_swap_file") {
		t.Error("should not flag normal file mount")
	}
}

func TestEditorBackup(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./config.bak:/app/config.bak"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_editor_backup") {
		t.Error("expected backup_editor_backup for .bak file")
	}
}

func TestEditorBackupOrig(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./settings.orig:/app/settings.orig"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_editor_backup") {
		t.Error("expected backup_editor_backup for .orig file")
	}
}

func TestNoEditorBackup(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./app.py:/app/app.py"},
	})
	r := Analyze(c)
	if findRule(r.Services, "backup_editor_backup") {
		t.Error("should not flag normal file mount")
	}
}

func TestVersionControlGit(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./.git:/app/.git"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_version_control") {
		t.Error("expected backup_version_control for .git directory mount")
	}
}

func TestVersionControlSvn(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./.svn:/app/.svn"},
	})
	r := Analyze(c)
	if !findRule(r.Services, "backup_version_control") {
		t.Error("expected backup_version_control for .svn directory mount")
	}
}

func TestNoVersionControl(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "app",
		Volumes: []string{"./src:/app/src"},
	})
	r := Analyze(c)
	if findRule(r.Services, "backup_version_control") {
		t.Error("should not flag normal directory mount")
	}
}

func TestMultipleFindings(t *testing.T) {
	c := mkCollected(compose.Service{
		Name: "db",
		Volumes: []string{
			"./db.sql:/init/db.sql",
			"./.git:/app/.git",
			"./data:/backup/data",
		},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestNoFindings(t *testing.T) {
	c := mkCollected(compose.Service{Name: "web"})
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

func TestFormatTextOutput(t *testing.T) {
	c := mkCollected(compose.Service{
		Name:    "db",
		Volumes: []string{"./db.sql:/init/db.sql"},
	})
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "Backup File Exposure") {
		t.Error("expected 'Backup File Exposure' in output")
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
