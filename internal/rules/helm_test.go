package rules

import (
	"path/filepath"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
)

func TestHelmFindingsPrivileged(t *testing.T) {
	values := []collect.HelmValues{{
		Path: "values.yaml",
		Findings: []collect.HelmValueFinding{
			{KeyPath: "securityContext.privileged", Value: "true", Line: 5},
		},
	}}
	fs := helmFindings(values)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].ID != "helm_insecure_default" {
		t.Errorf("ID: got %q", fs[0].ID)
	}
	if fs[0].Severity != SeverityCritical {
		t.Errorf("severity: got %s, want CRITICAL", fs[0].Severity)
	}
}

func TestHelmFindingsServiceType(t *testing.T) {
	values := []collect.HelmValues{{
		Path: "values.yaml",
		Findings: []collect.HelmValueFinding{
			{KeyPath: "service.type", Value: "LoadBalancer", Line: 3},
		},
	}}
	fs := helmFindings(values)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].Severity != SeverityHigh {
		t.Errorf("severity: got %s, want HIGH", fs[0].Severity)
	}
}

func TestHelmFindingsEmpty(t *testing.T) {
	fs := helmFindings(nil)
	if len(fs) != 0 {
		t.Errorf("expected 0 findings for nil input, got %d", len(fs))
	}
}

func TestHelmStackIntegration(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "helm-chart"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := collect.WalkAndCollect(dir)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(c.HelmValues) == 0 {
		t.Fatal("expected HelmValues to be collected from testdata/helm-chart")
	}
	fs := Evaluate(c)
	found := false
	for _, f := range fs {
		if f.ID == "helm_insecure_default" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected helm_insecure_default finding from helm-chart fixture")
	}
}
