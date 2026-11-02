package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/audittrail"
)

func runAuditTrail(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: tasia audit-trail [record|show|latest] [flags]")
		return fmt.Errorf("subcommand required")
	}

	sub := args[0]
	rest := args[1:]

	switch sub {
	case "record":
		return runAuditRecord(rest)
	case "show":
		return runAuditShow(rest)
	case "latest":
		return runAuditLatest(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown audit-trail subcommand: %s\n", sub)
		return fmt.Errorf("unknown subcommand: %s", sub)
	}
}

func runAuditRecord(args []string) error {
	fs := flag.NewFlagSet("audit-trail record", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	trail := fs.String("trail", "tasia-audit.json", "audit trail file")
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

	entry := audittrail.NewEntry(absPath, versionString(), findings)
	if err := audittrail.AppendEntry(*trail, entry); err != nil {
		return fmt.Errorf("appending entry: %w", err)
	}

	fmt.Printf("Recorded: %d findings, checksum %s\n", entry.FindingCount, entry.Checksum)
	return nil
}

func runAuditShow(args []string) error {
	fs := flag.NewFlagSet("audit-trail show", flag.ContinueOnError)
	trail := fs.String("trail", "tasia-audit.json", "audit trail file")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	t, err := audittrail.LoadTrail(*trail)
	if err != nil {
		return fmt.Errorf("loading trail: %w", err)
	}

	switch *format {
	case "json":
		data, _ := json.MarshalIndent(t, "", "  ")
		fmt.Println(string(data))
	default:
		fmt.Print(audittrail.FormatText(t))
	}
	return nil
}

func runAuditLatest(args []string) error {
	fs := flag.NewFlagSet("audit-trail latest", flag.ContinueOnError)
	trail := fs.String("trail", "tasia-audit.json", "audit trail file")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	entry, err := audittrail.LatestEntry(*trail)
	if err != nil {
		return fmt.Errorf("reading latest: %w", err)
	}

	switch *format {
	case "json":
		data, _ := json.MarshalIndent(entry, "", "  ")
		fmt.Println(string(data))
	default:
		fmt.Print(audittrail.FormatEntryText(entry))
	}
	return nil
}
