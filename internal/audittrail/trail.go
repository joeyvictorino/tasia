package audittrail

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joeyvictorino/tasia/internal/rules"
)

type AuditEntry struct {
	Timestamp    string         `json:"timestamp"`
	ScanPath     string         `json:"scan_path"`
	FindingCount int            `json:"finding_count"`
	BySeverity   map[string]int `json:"by_severity"`
	Checksum     string         `json:"checksum"`
	Version      string         `json:"version"`
}

type AuditTrail struct {
	Entries []AuditEntry `json:"entries"`
}

func NewEntry(scanPath, version string, findings []rules.Finding) AuditEntry {
	bySev := map[string]int{}
	for _, f := range findings {
		bySev[string(f.Severity)]++
	}

	h := sha256.New()
	for _, f := range findings {
		fmt.Fprintf(h, "%s:%s:%d\n", f.ID, f.File, f.Line)
	}
	checksum := fmt.Sprintf("%x", h.Sum(nil))

	return AuditEntry{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		ScanPath:     scanPath,
		FindingCount: len(findings),
		BySeverity:   bySev,
		Checksum:     checksum[:16],
		Version:      version,
	}
}

func AppendEntry(trailPath string, entry AuditEntry) error {
	trail, _ := LoadTrail(trailPath)
	trail.Entries = append(trail.Entries, entry)
	data, err := json.MarshalIndent(trail, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(trailPath, data, 0644)
}

func LoadTrail(trailPath string) (AuditTrail, error) {
	var trail AuditTrail
	data, err := os.ReadFile(trailPath)
	if err != nil {
		return trail, err
	}
	err = json.Unmarshal(data, &trail)
	return trail, err
}

func LatestEntry(trailPath string) (AuditEntry, error) {
	trail, err := LoadTrail(trailPath)
	if err != nil {
		return AuditEntry{}, err
	}
	if len(trail.Entries) == 0 {
		return AuditEntry{}, fmt.Errorf("audit trail is empty")
	}
	return trail.Entries[len(trail.Entries)-1], nil
}

func FormatText(trail AuditTrail) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Audit Trail (%d entries)\n\n", len(trail.Entries)))
	for i, e := range trail.Entries {
		b.WriteString(fmt.Sprintf("  #%d  %s\n", i+1, e.Timestamp))
		b.WriteString(fmt.Sprintf("      Path:     %s\n", e.ScanPath))
		b.WriteString(fmt.Sprintf("      Findings: %d  Checksum: %s  Version: %s\n", e.FindingCount, e.Checksum, e.Version))
		if len(e.BySeverity) > 0 {
			parts := make([]string, 0, len(e.BySeverity))
			for sev, n := range e.BySeverity {
				parts = append(parts, fmt.Sprintf("%s=%d", sev, n))
			}
			b.WriteString(fmt.Sprintf("      Severity: %s\n", strings.Join(parts, " ")))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func FormatEntryText(e AuditEntry) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Timestamp: %s\n", e.Timestamp))
	b.WriteString(fmt.Sprintf("Path:      %s\n", e.ScanPath))
	b.WriteString(fmt.Sprintf("Findings:  %d\n", e.FindingCount))
	b.WriteString(fmt.Sprintf("Checksum:  %s\n", e.Checksum))
	b.WriteString(fmt.Sprintf("Version:   %s\n", e.Version))
	for sev, n := range e.BySeverity {
		b.WriteString(fmt.Sprintf("  %s: %d\n", sev, n))
	}
	return b.String()
}
