package collect

import (
	"testing"
)

func TestParseHelmValuesInsecure(t *testing.T) {
	yaml := `
service:
  type: LoadBalancer
  port: 11434
securityContext:
  privileged: true
  runAsUser: 0
hostNetwork: true
persistence:
  hostPath: /data/models
`
	hv := ParseHelmValues("values.yaml", yaml)
	if len(hv.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %d: %+v", len(hv.Findings), hv.Findings)
	}

	keys := map[string]bool{}
	for _, f := range hv.Findings {
		keys[f.KeyPath] = true
	}
	want := []string{
		"service.type",
		"securityContext.privileged",
		"securityContext.runAsUser",
		"hostNetwork",
		"persistence.hostPath",
	}
	for _, k := range want {
		if !keys[k] {
			t.Errorf("missing finding for %s", k)
		}
	}
}

func TestParseHelmValuesSafe(t *testing.T) {
	yaml := `
service:
  type: ClusterIP
  port: 11434
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
hostNetwork: false
`
	hv := ParseHelmValues("values.yaml", yaml)
	if len(hv.Findings) != 0 {
		t.Errorf("safe values should produce 0 findings, got %d: %+v", len(hv.Findings), hv.Findings)
	}
}

func TestParseHelmValuesLineNumbers(t *testing.T) {
	yaml := `service:
  type: LoadBalancer
`
	hv := ParseHelmValues("values.yaml", yaml)
	if len(hv.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(hv.Findings))
	}
	if hv.Findings[0].Line == 0 {
		t.Error("finding should have a line number")
	}
}

func TestIsHelmValuesFile(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"values.yaml", true},
		{"values.yml", true},
		{"Values.yaml", true},
		{"Chart.yaml", false},
		{"deployment.yaml", false},
	}
	for _, tc := range cases {
		if got := IsHelmValuesFile(tc.name); got != tc.want {
			t.Errorf("IsHelmValuesFile(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
