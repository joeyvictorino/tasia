package snapshot

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestDriftIdentical(t *testing.T) {
	findings := []rules.Finding{
		{ID: "rule1", Severity: rules.SeverityHigh, File: "compose.yml", Title: "finding A"},
	}
	base := CreateSnapshot("/tmp", "1.0.0", findings)
	current := CreateSnapshot("/tmp", "1.0.0", findings)
	d := ComputeDrift(base, current)
	if len(d.NewFindings) != 0 {
		t.Errorf("new findings = %d, want 0", len(d.NewFindings))
	}
	if len(d.Resolved) != 0 {
		t.Errorf("resolved = %d, want 0", len(d.Resolved))
	}
	if d.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", d.Unchanged)
	}
	if d.DriftScore != 0 {
		t.Errorf("drift score = %f, want 0", d.DriftScore)
	}
}

func TestDriftNewFindings(t *testing.T) {
	base := CreateSnapshot("/tmp", "1.0.0", nil)
	current := CreateSnapshot("/tmp", "1.0.0", []rules.Finding{
		{ID: "rule1", Severity: rules.SeverityHigh, File: "compose.yml", Title: "new issue"},
	})
	d := ComputeDrift(base, current)
	if len(d.NewFindings) != 1 {
		t.Errorf("new findings = %d, want 1", len(d.NewFindings))
	}
	if d.DriftScore != 1.0 {
		t.Errorf("drift score = %f, want 1.0", d.DriftScore)
	}
}

func TestDriftResolvedFindings(t *testing.T) {
	base := CreateSnapshot("/tmp", "1.0.0", []rules.Finding{
		{ID: "rule1", Severity: rules.SeverityHigh, File: "compose.yml", Title: "old issue"},
	})
	current := CreateSnapshot("/tmp", "1.0.0", nil)
	d := ComputeDrift(base, current)
	if len(d.Resolved) != 1 {
		t.Errorf("resolved = %d, want 1", len(d.Resolved))
	}
	if len(d.NewFindings) != 0 {
		t.Errorf("new findings = %d, want 0", len(d.NewFindings))
	}
}

func TestDriftMixed(t *testing.T) {
	shared := rules.Finding{ID: "shared", Severity: rules.SeverityMedium, File: "compose.yml", Title: "shared finding"}
	base := CreateSnapshot("/tmp", "1.0.0", []rules.Finding{
		shared,
		{ID: "old", Severity: rules.SeverityLow, File: "Dockerfile", Title: "old only"},
	})
	current := CreateSnapshot("/tmp", "1.0.0", []rules.Finding{
		shared,
		{ID: "new", Severity: rules.SeverityHigh, File: "nginx.conf", Title: "new only"},
	})
	d := ComputeDrift(base, current)
	if d.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", d.Unchanged)
	}
	if len(d.NewFindings) != 1 {
		t.Errorf("new findings = %d, want 1", len(d.NewFindings))
	}
	if len(d.Resolved) != 1 {
		t.Errorf("resolved = %d, want 1", len(d.Resolved))
	}
	if d.DriftScore <= 0 || d.DriftScore >= 1.0 {
		t.Errorf("drift score = %f, want between 0 and 1", d.DriftScore)
	}
}

func TestDriftBothEmpty(t *testing.T) {
	base := CreateSnapshot("/tmp", "1.0.0", nil)
	current := CreateSnapshot("/tmp", "1.0.0", nil)
	d := ComputeDrift(base, current)
	if d.DriftScore != 0 {
		t.Errorf("drift score = %f, want 0", d.DriftScore)
	}
	if d.Unchanged != 0 {
		t.Errorf("unchanged = %d, want 0", d.Unchanged)
	}
}
