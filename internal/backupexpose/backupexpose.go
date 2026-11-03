package backupexpose

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type ServiceResult struct {
	Service  string    `json:"service"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices    int `json:"total_services"`
	TotalFindings    int `json:"total_findings"`
	BackupMount      int `json:"backup_mount"`
	SQLDump          int `json:"sql_dump"`
	ArchiveExpose    int `json:"archive_expose"`
	SwapFileExpose   int `json:"swap_file_expose"`
	EditorBackup     int `json:"editor_backup"`
	VersionControl   int `json:"version_control"`
}

var backupMountPatterns = []string{
	"/backup", "/backups", "/bak", "/dump", "/dumps",
	".bak:", ".backup:", ".old:",
}

var sqlDumpPatterns = []string{
	".sql:", ".sql.gz:", ".sql.bz2:", ".dump:",
	"mysqldump", "pg_dump", "mongodump",
}

var archiveExposePatterns = []string{
	".tar:", ".tar.gz:", ".tgz:", ".zip:", ".7z:", ".rar:",
	".tar.bz2:", ".gz:",
}

var swapFilePatterns = []string{
	".swp", ".swo", ".swn", "~", ".tmp",
}

var editorBackupPatterns = []string{
	".bak", ".orig", ".save", ".old", ".backup",
	"#", ".#",
}

var versionControlPatterns = []string{
	".git:", ".svn:", ".hg:", ".bzr:",
	"/.git/", "/.svn/", "/.hg/",
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}
	checkVolumes(&sr, svc)
	checkCommands(&sr, svc)
	return sr
}

func checkVolumes(sr *ServiceResult, svc compose.Service) {
	for _, vol := range svc.Volumes {
		lower := strings.ToLower(vol)

		if containsAny(lower, backupMountPatterns) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "backup_mount",
				Message: fmt.Sprintf("Service '%s' mounts a backup directory '%s'; backup files may contain sensitive data", svc.Name, truncate(vol, 60)),
			})
		}

		if containsAny(lower, sqlDumpPatterns) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "backup_sql_dump",
				Message: fmt.Sprintf("Service '%s' mounts SQL dump file '%s'; database dumps contain credentials and PII", svc.Name, truncate(vol, 60)),
			})
		}

		if containsAny(lower, archiveExposePatterns) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "backup_archive_expose",
				Message: fmt.Sprintf("Service '%s' mounts archive file '%s'; compressed archives may contain sensitive data", svc.Name, truncate(vol, 60)),
			})
		}

		if hasSwapFile(lower) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "backup_swap_file",
				Message: fmt.Sprintf("Service '%s' mounts potential swap/temp file '%s'; editor artifacts may leak file contents", svc.Name, truncate(vol, 60)),
			})
		}

		if hasEditorBackup(lower) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "medium",
				Rule:    "backup_editor_backup",
				Message: fmt.Sprintf("Service '%s' mounts editor backup file '%s'; backup copies may contain sensitive data", svc.Name, truncate(vol, 60)),
			})
		}

		if containsAny(lower, versionControlPatterns) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "backup_version_control",
				Message: fmt.Sprintf("Service '%s' mounts version control directory '%s'; exposes repository history and credentials", svc.Name, truncate(vol, 60)),
			})
		}
	}
}

func checkCommands(sr *ServiceResult, svc compose.Service) {
	allArgs := append(svc.Entrypoint, svc.Command...)
	joined := strings.Join(allArgs, " ")
	lower := strings.ToLower(joined)

	if containsAny(lower, sqlDumpPatterns) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "backup_sql_dump",
			Message: fmt.Sprintf("Service '%s' references SQL dump operations in entrypoint/command; ensure dumps are not exposed", svc.Name),
		})
	}
}

func hasSwapFile(s string) bool {
	for _, ext := range swapFilePatterns {
		if strings.HasSuffix(s, ext) || strings.Contains(s, ext+":") || strings.Contains(s, ext+"/") {
			return true
		}
	}
	return false
}

func hasEditorBackup(s string) bool {
	for _, ext := range editorBackupPatterns {
		if strings.HasSuffix(s, ext+":") || strings.Contains(s, ext+":/") {
			return true
		}
	}
	return false
}

func containsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "backup_mount":
				s.BackupMount++
			case "backup_sql_dump":
				s.SQLDump++
			case "backup_archive_expose":
				s.ArchiveExpose++
			case "backup_swap_file":
				s.SwapFileExpose++
			case "backup_editor_backup":
				s.EditorBackup++
			case "backup_version_control":
				s.VersionControl++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Backup File Exposure Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Backup mounts:          %d\n", r.Summary.BackupMount)
	fmt.Fprintf(&b, "  SQL dump exposure:      %d\n", r.Summary.SQLDump)
	fmt.Fprintf(&b, "  Archive exposure:       %d\n", r.Summary.ArchiveExpose)
	fmt.Fprintf(&b, "  Swap file exposure:     %d\n", r.Summary.SwapFileExpose)
	fmt.Fprintf(&b, "  Editor backup files:    %d\n", r.Summary.EditorBackup)
	fmt.Fprintf(&b, "  Version control dirs:   %d\n\n", r.Summary.VersionControl)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s\n", sr.Service)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		if len(sr.Findings) == 0 {
			fmt.Fprintf(&b, "    (no findings)\n")
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
