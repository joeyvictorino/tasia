package remediate

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestSuggestExposedInference(t *testing.T) {
	f := rules.Finding{ID: "exposed_inference", Title: "Inference API published"}
	r := Suggest(f)
	if r.Confidence != "high" {
		t.Errorf("confidence = %q, want high", r.Confidence)
	}
	if !strings.Contains(r.Patch, "127.0.0.1") {
		t.Error("patch should suggest 127.0.0.1 binding")
	}
	if r.RuleID != "exposed_inference" {
		t.Errorf("rule_id = %q, want exposed_inference", r.RuleID)
	}
}

func TestSuggestPrivilegedContainer(t *testing.T) {
	f := rules.Finding{ID: "privileged_container"}
	r := Suggest(f)
	if r.Confidence != "high" {
		t.Errorf("confidence = %q, want high", r.Confidence)
	}
	if !strings.Contains(r.Patch, "privileged: true") {
		t.Error("patch should reference privileged: true")
	}
}

func TestSuggestDockerSocketMount(t *testing.T) {
	f := rules.Finding{ID: "docker_socket_mount"}
	r := Suggest(f)
	if r.Confidence != "high" {
		t.Errorf("confidence = %q, want high", r.Confidence)
	}
	if !strings.Contains(r.Patch, "docker.sock") {
		t.Error("patch should reference docker.sock")
	}
}

func TestSuggestLatestImageWithTag(t *testing.T) {
	f := rules.Finding{ID: "latest_image", Evidence: "image: ollama/ollama:latest"}
	r := Suggest(f)
	if r.Confidence != "medium" {
		t.Errorf("confidence = %q, want medium", r.Confidence)
	}
	if !strings.Contains(r.Patch, ":latest") {
		t.Error("patch should reference :latest")
	}
}

func TestSuggestLatestImageNoTag(t *testing.T) {
	f := rules.Finding{ID: "latest_image", Evidence: "image: ollama/ollama"}
	r := Suggest(f)
	if !strings.Contains(r.Patch, "add a version tag") {
		t.Error("patch should suggest adding a version tag")
	}
}

func TestSuggestPermissiveCors(t *testing.T) {
	f := rules.Finding{ID: "permissive_cors"}
	r := Suggest(f)
	if !strings.Contains(r.Patch, "OLLAMA_ORIGINS") {
		t.Error("patch should reference OLLAMA_ORIGINS")
	}
}

func TestSuggestUnknownRule(t *testing.T) {
	f := rules.Finding{ID: "unknown_future_rule", Title: "Some new rule", Why: "reason", Fix: "do something"}
	r := Suggest(f)
	if r.Confidence != "low" {
		t.Errorf("confidence = %q, want low for unknown rule", r.Confidence)
	}
	if !strings.Contains(r.Description, "Review and fix") {
		t.Error("should have generic description for unknown rules")
	}
}

func TestSuggestAllReturnsCorrectCount(t *testing.T) {
	findings := []rules.Finding{
		{ID: "exposed_inference"},
		{ID: "privileged_container"},
		{ID: "latest_image"},
	}
	remediations := SuggestAll(findings)
	if len(remediations) != 3 {
		t.Errorf("got %d remediations, want 3", len(remediations))
	}
}

func TestFormatTextEmpty(t *testing.T) {
	text := FormatText(nil)
	if !strings.Contains(text, "No findings") {
		t.Error("empty list should say no findings")
	}
}

func TestFormatTextNonEmpty(t *testing.T) {
	remediations := SuggestAll([]rules.Finding{
		{ID: "exposed_inference"},
		{ID: "privileged_container"},
	})
	text := FormatText(remediations)
	if !strings.Contains(text, "exposed_inference") {
		t.Error("should contain rule ID")
	}
	if !strings.Contains(text, "Suggested change") {
		t.Error("should contain patch section")
	}
}

func TestSuggestKubeRules(t *testing.T) {
	cases := []struct {
		id         string
		confidence string
		contains   string
	}{
		{"kube_privileged", "high", "privileged: false"},
		{"kube_run_as_root", "high", "runAsNonRoot"},
		{"kube_host_network", "high", "hostNetwork: false"},
		{"kube_host_path", "medium", "persistentVolumeClaim"},
		{"kube_no_network_policy", "medium", "NetworkPolicy"},
		{"kube_exposed_service", "medium", "ClusterIP"},
	}
	for _, tc := range cases {
		r := Suggest(rules.Finding{ID: tc.id})
		if r.Confidence != tc.confidence {
			t.Errorf("%s: confidence = %q, want %q", tc.id, r.Confidence, tc.confidence)
		}
		if !strings.Contains(r.Patch, tc.contains) {
			t.Errorf("%s: patch should contain %q", tc.id, tc.contains)
		}
	}
}

func TestSuggestAgentRules(t *testing.T) {
	cases := []struct {
		id         string
		confidence string
	}{
		{"agent_auto_approve", "high"},
		{"agent_shared_secret", "medium"},
		{"agent_test_mount", "high"},
		{"agent_auto_restart", "high"},
	}
	for _, tc := range cases {
		r := Suggest(rules.Finding{ID: tc.id})
		if r.Confidence != tc.confidence {
			t.Errorf("%s: confidence = %q, want %q", tc.id, r.Confidence, tc.confidence)
		}
		if r.Patch == "" {
			t.Errorf("%s: patch should not be empty", tc.id)
		}
	}
}

func TestSuggestVectorAuthChroma(t *testing.T) {
	f := rules.Finding{ID: "vector_db_no_auth", Evidence: "chromadb/chroma"}
	r := Suggest(f)
	if !strings.Contains(r.Patch, "CHROMA") {
		t.Error("should suggest Chroma auth config")
	}
}

func TestSuggestVectorAuthWeaviate(t *testing.T) {
	f := rules.Finding{ID: "vector_db_no_auth", Evidence: "weaviate/weaviate"}
	r := Suggest(f)
	if !strings.Contains(r.Patch, "WEAVIATE") || !strings.Contains(r.Patch, "APIKEY") {
		t.Error("should suggest Weaviate auth config")
	}
}

func TestSuggestExposedVariants(t *testing.T) {
	for _, id := range []string{"exposed_ui", "exposed_vector", "exposed_datastore", "exposed_agent_runtime"} {
		r := Suggest(rules.Finding{ID: id})
		if r.Confidence != "high" {
			t.Errorf("%s: confidence = %q, want high", id, r.Confidence)
		}
		if !strings.Contains(r.Patch, "127.0.0.1") {
			t.Errorf("%s: patch should suggest 127.0.0.1", id)
		}
	}
}
