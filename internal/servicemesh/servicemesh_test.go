package servicemesh

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestAnalyzeEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{})
	if r.Summary.TotalServices != 0 {
		t.Fatalf("expected 0 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.MeshDetected {
		t.Fatal("expected no mesh detected")
	}
}

func TestNoMeshNoFindings(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{{
				Name:  "app",
				Image: "myapp:latest",
			}},
		}},
	}
	r := Analyze(c)
	if r.Summary.MeshDetected {
		t.Fatal("expected no mesh detected")
	}
	if r.Summary.Findings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.Findings)
	}
}

func TestMeshDetectedIstio(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{{
				Name:  "proxy",
				Image: "istio/proxyv2:1.20",
			}},
		}},
	}
	r := Analyze(c)
	if !r.Summary.MeshDetected {
		t.Fatal("expected mesh detected")
	}
	if r.Summary.MeshType != "istio" {
		t.Fatalf("expected istio, got %q", r.Summary.MeshType)
	}
}

func TestMTLSDisabled(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{{
				Name:        "proxy",
				Image:       "envoyproxy/envoy:v1.28",
				Environment: []string{"MTLS_MODE=permissive"},
			}},
		}},
	}
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "mtls" && f.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected high severity mTLS finding")
	}
}

func TestSidecarInjectionMissing(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{
				{Name: "proxy", Image: "istio/proxyv2:1.20"},
				{Name: "app", Image: "myapp:latest"},
			},
		}},
	}
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Service == "app" && f.Category == "sidecar" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected sidecar injection finding for app")
	}
}

func TestNetworkModeHostProxy(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{{
				Name:        "proxy",
				Image:       "envoyproxy/envoy:v1.28",
				NetworkMode: "host",
			}},
		}},
	}
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "network" && f.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected high severity network finding")
	}
}

func TestAccessLoggingDisabled(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{{
				Name:        "proxy",
				Image:       "envoyproxy/envoy:v1.28",
				Environment: []string{"ACCESS_LOG=false"},
			}},
		}},
	}
	r := Analyze(c)
	found := false
	for _, f := range r.Findings {
		if f.Category == "observability" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected observability finding")
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	r := Analyze(&collect.Collected{})
	out := FormatText(r)
	if !strings.Contains(out, "Service Mesh Configuration Audit") {
		t.Fatal("expected header")
	}
}

func TestScoreDecreasesWithFindings(t *testing.T) {
	clean := Analyze(&collect.Collected{})
	dirty := Analyze(&collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{{
				Name:        "proxy",
				Image:       "envoyproxy/envoy:v1.28",
				NetworkMode: "host",
				Environment: []string{"MTLS_MODE=false"},
			}},
		}},
	})
	if dirty.Summary.Score >= clean.Summary.Score {
		t.Fatal("expected lower score with findings")
	}
}

func TestLinkerdDetection(t *testing.T) {
	c := &collect.Collected{
		ComposeFiles: []compose.File{{
			Services: []compose.Service{{
				Name:  "proxy",
				Image: "linkerd/proxy:stable-2.14",
			}},
		}},
	}
	r := Analyze(c)
	if r.Summary.MeshType != "linkerd" {
		t.Fatalf("expected linkerd, got %q", r.Summary.MeshType)
	}
}
