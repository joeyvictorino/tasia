package cgroupv2

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyze_V1OnlyKeys(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "worker", Environment: []string{"cpu_shares=512", "blkio_weight=300"}},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Summary.V1Only != 1 {
		t.Errorf("expected 1 v1-only service, got %d", r.Summary.V1Only)
	}
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	if r.Services[0].CgroupV2Ready {
		t.Error("expected service to not be v2 ready")
	}
	if len(r.Services[0].CgroupV1Keys) != 2 {
		t.Errorf("expected 2 v1 keys, got %d", len(r.Services[0].CgroupV1Keys))
	}
}

func TestAnalyze_MixedConfig(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "app", CPUs: "2.0", MemLimit: "1g", Environment: []string{"cpu_shares=512"}},
				},
			},
		},
	}

	r := Analyze(collected)
	found := false
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "cgroupv2_mixed_config" {
				found = true
				if f.Severity != "high" {
					t.Errorf("expected high severity, got %s", f.Severity)
				}
			}
		}
	}
	if !found {
		t.Error("expected cgroupv2_mixed_config finding")
	}
}

func TestAnalyze_CgroupMount(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "monitor", Volumes: []string{"/sys/fs/cgroup:/sys/fs/cgroup"}},
				},
			},
		},
	}

	r := Analyze(collected)
	found := false
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "cgroupv2_cgroup_mount" {
				found = true
				if f.Severity != "high" {
					t.Errorf("expected high severity for writable cgroup mount, got %s", f.Severity)
				}
			}
		}
	}
	if !found {
		t.Error("expected cgroupv2_cgroup_mount finding")
	}
}

func TestAnalyze_CgroupMountReadOnly(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "observer", Volumes: []string{"/sys/fs/cgroup:/sys/fs/cgroup:ro"}},
				},
			},
		},
	}

	r := Analyze(collected)
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "cgroupv2_cgroup_mount" && f.Severity != "medium" {
				t.Errorf("expected medium severity for read-only cgroup mount, got %s", f.Severity)
			}
		}
	}
}

func TestAnalyze_SystempathsUnconfined(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "app", SecurityOpt: []string{"systempaths=unconfined"}},
				},
			},
		},
	}

	r := Analyze(collected)
	found := false
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "cgroupv2_systempaths_unconfined" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected cgroupv2_systempaths_unconfined finding")
	}
}

func TestAnalyze_V2Ready(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "clean", CPUs: "1.0", MemLimit: "512m", PidsLimit: 100},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Summary.V2Ready != 1 {
		t.Errorf("expected 1 v2-ready service, got %d", r.Summary.V2Ready)
	}
	if !r.Services[0].CgroupV2Ready {
		t.Error("expected service to be v2 ready")
	}
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	r := Report{
		Services: []ServiceResult{
			{
				Name:          "worker",
				File:          "docker-compose.yml",
				CgroupV2Ready: false,
				CgroupV1Keys:  []string{"cpu_shares"},
				Findings: []Finding{
					{RuleID: "cgroupv2_v1_only_key", Severity: "medium", Detail: "test"},
				},
			},
		},
		Summary: Summary{TotalServices: 1, V1Only: 1, TotalFindings: 1},
	}
	text := FormatText(r)
	if !strings.Contains(text, "Cgroup v2 Migration") {
		t.Error("expected header in text output")
	}
	if !strings.Contains(text, "v1-dependent") {
		t.Error("expected v1-dependent status in text")
	}
}

func TestReportJSON(t *testing.T) {
	r := Report{
		Services: []ServiceResult{{Name: "svc", File: "f.yml", CgroupV2Ready: true}},
		Summary:  Summary{TotalServices: 1, V2Ready: 1},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	if !strings.Contains(string(b), `"cgroup_v2_ready":true`) {
		t.Error("expected cgroup_v2_ready in JSON")
	}
}
