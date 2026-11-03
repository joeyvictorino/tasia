package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHistoryListEmpty(t *testing.T) {
	dir := t.TempDir()
	err := runHistory([]string{"list", "--path", dir})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHistoryListJSON(t *testing.T) {
	dir := t.TempDir()
	err := runHistory([]string{"list", "--path", dir, "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHistoryRecord(t *testing.T) {
	dir := t.TempDir()
	err := runHistory([]string{"record", "--path", dir})
	if err != nil {
		t.Fatal(err)
	}

	data, _, err := loadHistory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(data.Records))
	}
}

func TestHistoryRecordMultiple(t *testing.T) {
	dir := t.TempDir()
	runHistory([]string{"record", "--path", dir})
	runHistory([]string{"record", "--path", dir})
	runHistory([]string{"record", "--path", dir})

	data, _, _ := loadHistory(dir)
	if len(data.Records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(data.Records))
	}
}

func TestHistoryListLast(t *testing.T) {
	dir := t.TempDir()
	runHistory([]string{"record", "--path", dir})
	runHistory([]string{"record", "--path", dir})
	runHistory([]string{"record", "--path", dir})

	err := runHistory([]string{"list", "--path", dir, "--last", "2"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHistoryClear(t *testing.T) {
	dir := t.TempDir()
	runHistory([]string{"record", "--path", dir})

	err := runHistory([]string{"clear", "--path", dir})
	if err != nil {
		t.Fatal(err)
	}

	histPath := filepath.Join(dir, ".tasia", "history.json")
	if _, err := os.Stat(histPath); !os.IsNotExist(err) {
		t.Fatal("expected history file to be deleted")
	}
}

func TestHistoryClearMissing(t *testing.T) {
	dir := t.TempDir()
	err := runHistory([]string{"clear", "--path", dir})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHistoryUnknownSubcommand(t *testing.T) {
	err := runHistory([]string{"frobnicate"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHistoryDefaultSubcommand(t *testing.T) {
	err := runHistory(nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHistoryRoundtrip(t *testing.T) {
	dir := t.TempDir()
	histPath := filepath.Join(dir, ".tasia", "history.json")

	data := &historyData{
		Records: []historyRecord{
			{Timestamp: "2024-01-01T00:00:00Z", Decision: "PASS", Total: 0, Score: 100},
		},
	}
	if err := saveHistory(histPath, data); err != nil {
		t.Fatal(err)
	}

	loaded, _, err := loadHistory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Records) != 1 || loaded.Records[0].Score != 100 {
		t.Fatal("roundtrip failed")
	}
}

func TestReportDecide(t *testing.T) {
	dec, _ := report_decide(nil)
	if dec != "PASS" {
		t.Fatalf("expected PASS, got %s", dec)
	}
}
