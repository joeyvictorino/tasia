package registryauth

import (
	"encoding/json"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func collected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func hasRule(sr ServiceResult, rule string) bool {
	for _, f := range sr.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestInsecureHTTPRegistry(t *testing.T) {
	c := collected(compose.Service{
		Name:  "agent",
		Image: "http://myregistry.local/ai-agent:latest",
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "registryauth_insecure_http") {
		t.Error("expected registryauth_insecure_http for http:// image")
	}
	if r.Summary.InsecureRegistries != 1 {
		t.Errorf("expected 1 insecure registry, got %d", r.Summary.InsecureRegistries)
	}
}

func TestPrivateRegistryNoPin(t *testing.T) {
	c := collected(compose.Service{
		Name:  "model",
		Image: "registry.internal.co/ml/model:v2",
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "registryauth_private_no_pin") {
		t.Error("expected registryauth_private_no_pin for undigested private image")
	}
	if r.Summary.UnpinnedImages != 1 {
		t.Errorf("expected 1 unpinned, got %d", r.Summary.UnpinnedImages)
	}
}

func TestPrivateRegistryWithDigest(t *testing.T) {
	c := collected(compose.Service{
		Name:  "model",
		Image: "registry.internal.co/ml/model@sha256:abcdef1234567890",
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "registryauth_private_no_pin") {
		t.Error("should not flag pinned image")
	}
}

func TestPublicRegistryNotFlagged(t *testing.T) {
	c := collected(compose.Service{
		Name:  "web",
		Image: "ghcr.io/org/app:latest",
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "registryauth_private_no_pin") {
		t.Error("should not flag public registry")
	}
}

func TestLocalhostRegistry(t *testing.T) {
	c := collected(compose.Service{
		Name:  "dev",
		Image: "localhost:5000/myapp:dev",
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "registryauth_localhost_registry") {
		t.Error("expected registryauth_localhost_registry")
	}
}

func TestDefaultPortRegistry(t *testing.T) {
	c := collected(compose.Service{
		Name:  "ci",
		Image: "registry.corp.io:5000/build/runner:latest",
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "registryauth_default_port") {
		t.Error("expected registryauth_default_port for :5000")
	}
	if r.Summary.MissingAuth < 1 {
		t.Errorf("expected missing auth count >= 1, got %d", r.Summary.MissingAuth)
	}
}

func TestPlaintextCredInEnv(t *testing.T) {
	c := collected(compose.Service{
		Name:        "puller",
		Image:       "registry.corp.io/app:v1",
		Environment: []string{"REGISTRY_PASSWORD=s3cret123"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "registryauth_plaintext_cred") {
		t.Error("expected registryauth_plaintext_cred for plaintext password")
	}
	if r.Summary.PlaintextCredentials != 1 {
		t.Errorf("expected 1 plaintext credential, got %d", r.Summary.PlaintextCredentials)
	}
}

func TestSecretRefNotFlagged(t *testing.T) {
	c := collected(compose.Service{
		Name:        "puller",
		Image:       "registry.corp.io/app:v1",
		Environment: []string{"REGISTRY_PASSWORD=${REGISTRY_PASSWORD}"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "registryauth_plaintext_cred") {
		t.Error("should not flag variable reference as plaintext")
	}
}

func TestDockerConfigExposure(t *testing.T) {
	c := collected(compose.Service{
		Name:        "builder",
		Image:       "docker:latest",
		Environment: []string{"DOCKER_CONFIG=/home/user/.docker"},
	})
	r := Analyze(c)
	if !hasRule(r.Services[0], "registryauth_config_exposure") {
		t.Error("expected registryauth_config_exposure for non-secrets DOCKER_CONFIG")
	}
}

func TestDockerConfigFromSecretsSafe(t *testing.T) {
	c := collected(compose.Service{
		Name:        "builder",
		Image:       "docker:latest",
		Environment: []string{"DOCKER_CONFIG=/run/secrets/docker-config"},
	})
	r := Analyze(c)
	if hasRule(r.Services[0], "registryauth_config_exposure") {
		t.Error("should not flag DOCKER_CONFIG pointing to /run/secrets")
	}
}

func TestCleanService(t *testing.T) {
	c := collected(compose.Service{
		Name:  "clean",
		Image: "nginx:latest",
	})
	r := Analyze(c)
	if len(r.Services[0].Findings) != 0 {
		t.Errorf("expected 0 findings for clean service, got %d", len(r.Services[0].Findings))
	}
}

func TestEmptyCollected(t *testing.T) {
	c := &collect.Collected{Root: "/test"}
	r := Analyze(c)
	if r.Summary.TotalServices != 0 {
		t.Errorf("expected 0 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatText(t *testing.T) {
	c := collected(compose.Service{
		Name:  "agent",
		Image: "http://bad.io/img:v1",
	})
	r := Analyze(c)
	text := FormatText(r)
	if text == "" {
		t.Error("expected non-empty text output")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	c := collected(compose.Service{
		Name:  "svc",
		Image: "localhost:5000/app:v1",
	})
	r := Analyze(c)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Report
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service after round-trip, got %d", r2.Summary.TotalServices)
	}
}

func TestExtractRegistry(t *testing.T) {
	tests := []struct {
		image string
		want  string
	}{
		{"nginx:latest", ""},
		{"ghcr.io/org/app:v1", "ghcr.io"},
		{"registry.corp.io:5000/app:v1", "registry.corp.io:5000"},
		{"localhost:5000/img:v1", "localhost:5000"},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractRegistry(tt.image)
		if got != tt.want {
			t.Errorf("extractRegistry(%q) = %q, want %q", tt.image, got, tt.want)
		}
	}
}

func TestMultipleFindings(t *testing.T) {
	c := collected(compose.Service{
		Name:        "allbad",
		Image:       "http://localhost:5000/secret-app:latest",
		Environment: []string{"REGISTRY_TOKEN=plaintext-token"},
	})
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Errorf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}
