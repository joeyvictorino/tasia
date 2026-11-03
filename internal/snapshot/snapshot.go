package snapshot

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/joeyvictorino/tasia/internal/rules"
)

type SnapshotFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Message  string `json:"message"`
	Hash     string `json:"hash"`
}

type Snapshot struct {
	Version      string         `json:"version"`
	Timestamp    string         `json:"timestamp"`
	Path         string         `json:"path"`
	Checksum     string         `json:"checksum"`
	RuleCount    int            `json:"rule_count"`
	FindingCount int            `json:"finding_count"`
	BySeverity   map[string]int `json:"by_severity"`
	Findings     []SnapshotFinding `json:"findings"`
}

func hashFinding(ruleID, file, message string) string {
	data := fmt.Sprintf("%s:%s:%s", ruleID, file, message)
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h)
}

func computeChecksum(findings []SnapshotFinding) string {
	hashes := make([]string, len(findings))
	for i, f := range findings {
		hashes[i] = f.Hash
	}
	sort.Strings(hashes)
	combined := ""
	for _, h := range hashes {
		combined += h
	}
	sum := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", sum[:16])
}

func CreateSnapshot(path, version string, findings []rules.Finding) Snapshot {
	catalogRules := rules.Catalog()
	sfList := make([]SnapshotFinding, len(findings))
	bySev := map[string]int{}
	for i, f := range findings {
		sfList[i] = SnapshotFinding{
			RuleID:   f.ID,
			Severity: string(f.Severity),
			File:     f.File,
			Message:  f.Title,
			Hash:     hashFinding(f.ID, f.File, f.Title),
		}
		bySev[string(f.Severity)]++
	}

	s := Snapshot{
		Version:      version,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Path:         path,
		RuleCount:    len(catalogRules),
		FindingCount: len(sfList),
		BySeverity:   bySev,
		Findings:     sfList,
	}
	s.Checksum = computeChecksum(sfList)
	return s
}

func SaveSnapshot(s Snapshot, outPath string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, data, 0644)
}

func LoadSnapshot(path string) (Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}
