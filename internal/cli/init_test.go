package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	err := Run([]string{"init", "--path", dir})
	if err != nil {
		t.Fatalf("init returned error: %v", err)
	}

	rcPath := filepath.Join(dir, ".tasiarc.yaml")
	if _, err := os.Stat(rcPath); os.IsNotExist(err) {
		t.Error(".tasiarc.yaml was not created")
	}

	ignorePath := filepath.Join(dir, ".tasiaignore")
	if _, err := os.Stat(ignorePath); os.IsNotExist(err) {
		t.Error(".tasiaignore was not created")
	}
}

func TestInitConfigContainsRules(t *testing.T) {
	dir := t.TempDir()
	if err := Run([]string{"init", "--path", dir}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".tasiarc.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "severities:") {
		t.Error("config should contain severities section")
	}
	if !strings.Contains(content, "exposed_inference") {
		t.Error("config should contain exposed_inference rule")
	}
	if !strings.Contains(content, "tf_ecs_privileged") {
		t.Error("config should contain tf_ecs_privileged rule")
	}
	if !strings.Contains(content, "# --- compose ---") {
		t.Error("config should contain category headers")
	}
}

func TestInitIgnoreContainsPatterns(t *testing.T) {
	dir := t.TempDir()
	if err := Run([]string{"init", "--path", dir}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".tasiaignore"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "node_modules") {
		t.Error("ignore should mention node_modules")
	}
}

func TestInitRefusesIfExists(t *testing.T) {
	dir := t.TempDir()

	rcPath := filepath.Join(dir, ".tasiarc.yaml")
	if err := os.WriteFile(rcPath, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Run([]string{"init", "--path", dir})
	if err == nil {
		t.Error("init should refuse when .tasiarc.yaml already exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' in error, got: %v", err)
	}
}

func TestInitRefusesIfIgnoreExists(t *testing.T) {
	dir := t.TempDir()

	ignorePath := filepath.Join(dir, ".tasiaignore")
	if err := os.WriteFile(ignorePath, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Run([]string{"init", "--path", dir})
	if err == nil {
		t.Error("init should refuse when .tasiaignore already exists")
	}
}

func TestGenerateConfigHasAllRules(t *testing.T) {
	content := generateConfig()

	expected := []string{
		"docker_socket_mount", "privileged_container", "permissive_cors",
		"kube_privileged", "helm_insecure_default",
		"tf_gcp_firewall_ingress_all", "tf_azure_nsg_ingress_all",
		"tf_lambda_admin_role", "tf_ecs_privileged",
	}
	for _, id := range expected {
		if !strings.Contains(content, id) {
			t.Errorf("config should contain rule %s", id)
		}
	}
}
