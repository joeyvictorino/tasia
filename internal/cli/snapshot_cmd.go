package cli

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/snapshot"
)

func runSnapshot(args []string) error {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	output := fs.String("output", "tasia-snapshot.json", "output file")
	recursive := fs.Bool("recursive", false, "scan nested directories")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	var findings = scanDir(absPath)
	if *recursive {
		findings = scanRecursive(absPath)
	}

	s := snapshot.CreateSnapshot(absPath, versionString(), findings)
	if err := snapshot.SaveSnapshot(s, *output); err != nil {
		return fmt.Errorf("writing snapshot: %w", err)
	}

	fmt.Printf("Snapshot saved: %d findings, checksum %s\n", s.FindingCount, s.Checksum)
	fmt.Printf("  Path:   %s\n", s.Path)
	fmt.Printf("  Output: %s\n", *output)
	for sev, count := range s.BySeverity {
		fmt.Printf("  %s: %d\n", sev, count)
	}
	return nil
}
