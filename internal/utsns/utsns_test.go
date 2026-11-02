package utsns

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyze_HostUTS(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "agent", UtsMode: "host"},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Summary.HostUtsNamespace != 1 {
		t.Errorf("expected 1 host UTS namespace finding, got %d", r.Summary.HostUtsNamespace)
	}
	if len(r.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(r.Services))
	}
	found := false
	for _, f := range r.Services[0].Findings {
		if f.RuleID == "utsns_host_uts" {
			found = true
			if f.Severity != "high" {
				t.Errorf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected utsns_host_uts finding")
	}
}

func TestAnalyze_HostnameEnv(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "worker", Environment: []string{"HOSTNAME=$(hostname)"}},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Summary.HostnameExposed != 1 {
		t.Errorf("expected 1 hostname exposed finding, got %d", r.Summary.HostnameExposed)
	}
}

func TestAnalyze_NetworkHostUTSLeak(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "proxy", NetworkMode: "host"},
				},
			},
		},
	}

	r := Analyze(collected)
	found := false
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "utsns_network_host_uts_leak" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected utsns_network_host_uts_leak finding for host network mode without UTS")
	}
}

func TestAnalyze_HostIdentityMount(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "app", Volumes: []string{"/etc/hostname:/etc/hostname:ro", "/etc/hosts:/etc/hosts"}},
				},
			},
		},
	}

	r := Analyze(collected)
	count := 0
	for _, s := range r.Services {
		for _, f := range s.Findings {
			if f.RuleID == "utsns_host_identity_mount" {
				count++
			}
		}
	}
	if count != 2 {
		t.Errorf("expected 2 host identity mount findings, got %d", count)
	}
}

func TestAnalyze_Clean(t *testing.T) {
	collected := &collect.Collected{
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "safe"},
				},
			},
		},
	}

	r := Analyze(collected)
	if r.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings for clean service, got %d", r.Summary.TotalFindings)
	}
}

func TestFormatText(t *testing.T) {
	r := Report{
		Services: []ServiceResult{
			{
				Name:    "agent",
				File:    "docker-compose.yml",
				UtsMode: "host",
				Findings: []Finding{
					{
						Service:     "agent",
						File:        "docker-compose.yml",
						RuleID:      "utsns_host_uts",
						Severity:    "high",
						Detail:      "test detail",
						Remediation: "test fix",
					},
				},
			},
		},
		Summary: Summary{
			TotalServices:    1,
			HostUtsNamespace: 1,
			TotalFindings:    1,
		},
	}
	text := FormatText(r)
	if !strings.Contains(text, "UTS Namespace") {
		t.Error("expected header in text output")
	}
	if !strings.Contains(text, "utsns_host_uts") {
		t.Error("expected rule ID in text output")
	}
}

func TestReportJSON(t *testing.T) {
	r := Report{
		Services: []ServiceResult{{Name: "svc", File: "f.yml"}},
		Summary:  Summary{TotalServices: 1},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	if !strings.Contains(string(b), `"total_services":1`) {
		t.Error("expected total_services in JSON")
	}
}
