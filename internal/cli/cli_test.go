package cli

import (
	"testing"
)

func TestRunHelp(t *testing.T) {
	// just ensure does not panic on known paths
	err := Run([]string{"help"})
	if err != nil {
		t.Log("help returned err (ok for usage)")
	}
}

func TestUnknown(t *testing.T) {
	err := Run([]string{"bogus-cmd"})
	if err == nil {
		t.Error("expected error on unknown")
	}
}

func TestValidateFailOn(t *testing.T) {
	for _, ok := range []string{"", "critical", "high", "medium", "low", "HIGH", " medium "} {
		if err := validateFailOn(ok); err != nil {
			t.Errorf("validateFailOn(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"hgih", "none", "info", "3"} {
		if err := validateFailOn(bad); err == nil {
			t.Errorf("validateFailOn(%q) = nil, want error", bad)
		}
	}
}

func TestCIRejectsInvalidFailOn(t *testing.T) {
	// Must error before touching the filesystem, so the path does not matter.
	if err := Run([]string{"ci", "--path", t.TempDir(), "--fail-on", "hgih"}); err == nil {
		t.Error("expected error for invalid --fail-on on ci")
	}
	if err := Run([]string{"review", "--path", t.TempDir(), "--fail-on", "hgih", "--no-write"}); err == nil {
		t.Error("expected error for invalid --fail-on on review")
	}
}
