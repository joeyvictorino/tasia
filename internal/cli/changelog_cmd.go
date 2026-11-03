package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

func runChangelog(args []string) error {
	fs := flag.NewFlagSet("tasia changelog", flag.ContinueOnError)
	trail := fs.String("trail", "tasia-audit.json", "audit trail file")
	format := fs.String("format", "text", "output format: text or json")
	limit := fs.Int("limit", 0, "max entries to show (0 = all)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	data, err := os.ReadFile(*trail)
	if err != nil {
		return fmt.Errorf("reading trail: %w", err)
	}

	var entries []changelogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("parsing trail: %w", err)
	}

	result := buildChangelog(entries)
	if *limit > 0 && len(result.Changes) > *limit {
		result.Changes = result.Changes[:*limit]
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default:
		fmt.Print(formatChangelogText(result))
		return nil
	}
}

type changelogEntry struct {
	Timestamp    string   `json:"timestamp"`
	Path         string   `json:"path"`
	Version      string   `json:"version"`
	FindingCount int      `json:"finding_count"`
	Checksum     string   `json:"checksum"`
	Findings     []string `json:"findings,omitempty"`
}

type changelogChange struct {
	Timestamp    string   `json:"timestamp"`
	Version      string   `json:"version"`
	FindingCount int      `json:"finding_count"`
	Delta        int      `json:"delta"`
	Introduced   []string `json:"introduced,omitempty"`
	Resolved     []string `json:"resolved,omitempty"`
}

type changelogResult struct {
	Changes       []changelogChange `json:"changes"`
	TotalEntries  int               `json:"total_entries"`
	NetDelta      int               `json:"net_delta"`
	FirstScan     string            `json:"first_scan"`
	LastScan      string            `json:"last_scan"`
}

func buildChangelog(entries []changelogEntry) changelogResult {
	if len(entries) == 0 {
		return changelogResult{}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp < entries[j].Timestamp
	})

	var changes []changelogChange
	for i, e := range entries {
		c := changelogChange{
			Timestamp:    e.Timestamp,
			Version:      e.Version,
			FindingCount: e.FindingCount,
		}
		if i == 0 {
			c.Delta = e.FindingCount
			c.Introduced = e.Findings
		} else {
			prev := entries[i-1]
			c.Delta = e.FindingCount - prev.FindingCount

			prevSet := toSet(prev.Findings)
			currSet := toSet(e.Findings)

			for _, f := range e.Findings {
				if !prevSet[f] {
					c.Introduced = append(c.Introduced, f)
				}
			}
			for _, f := range prev.Findings {
				if !currSet[f] {
					c.Resolved = append(c.Resolved, f)
				}
			}
		}
		changes = append(changes, c)
	}

	netDelta := 0
	if len(entries) > 1 {
		netDelta = entries[len(entries)-1].FindingCount - entries[0].FindingCount
	}

	return changelogResult{
		Changes:      changes,
		TotalEntries: len(entries),
		NetDelta:     netDelta,
		FirstScan:    entries[0].Timestamp,
		LastScan:     entries[len(entries)-1].Timestamp,
	}
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func formatChangelogText(r changelogResult) string {
	var b strings.Builder
	b.WriteString("Security Changelog\n")
	b.WriteString("========================================\n")
	fmt.Fprintf(&b, "Scans: %d | Period: %s to %s | Net delta: %+d\n\n",
		r.TotalEntries, formatTS(r.FirstScan), formatTS(r.LastScan), r.NetDelta)

	for _, c := range r.Changes {
		delta := fmt.Sprintf("%+d", c.Delta)
		fmt.Fprintf(&b, "[%s] v%s  findings: %d (%s)\n",
			formatTS(c.Timestamp), c.Version, c.FindingCount, delta)
		for _, f := range c.Introduced {
			fmt.Fprintf(&b, "  + %s\n", f)
		}
		for _, f := range c.Resolved {
			fmt.Fprintf(&b, "  - %s\n", f)
		}
	}
	return b.String()
}

func formatTS(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.Format("2006-01-02 15:04")
}
