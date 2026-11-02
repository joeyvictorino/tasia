package rules

import (
	"path/filepath"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
)

func TestKubeServiceLoadBalancer(t *testing.T) {
	manifests := []collect.KubeManifest{{
		Path:        "ollama-svc.yaml",
		Kind:        "Service",
		Name:        "ollama-svc",
		ServiceType: "LoadBalancer",
		ServicePorts: []collect.KubeServicePort{{Port: 11434, Line: 10}},
	}}
	fs := kubeFindings(manifests)
	found := false
	for _, f := range fs {
		if f.ID == "kube_exposed_service" {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("severity: got %s, want HIGH", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected kube_exposed_service finding for LoadBalancer")
	}
}

func TestKubeServiceClusterIP(t *testing.T) {
	manifests := []collect.KubeManifest{{
		Path:        "safe-svc.yaml",
		Kind:        "Service",
		Name:        "safe-svc",
		ServiceType: "ClusterIP",
		ServicePorts: []collect.KubeServicePort{{Port: 11434, Line: 10}},
	}}
	fs := kubeFindings(manifests)
	for _, f := range fs {
		if f.ID == "kube_exposed_service" {
			t.Error("ClusterIP service should not produce kube_exposed_service finding")
		}
	}
}

func TestKubePrivilegedContainer(t *testing.T) {
	manifests := []collect.KubeManifest{{
		Path: "deploy.yaml",
		Kind: "Deployment",
		Name: "ollama",
		Containers: []collect.KubeContainer{{
			Name:           "ollama",
			Privileged:     true,
			PrivilegedLine: 15,
		}},
	}}
	fs := kubeFindings(manifests)
	found := false
	for _, f := range fs {
		if f.ID == "kube_privileged" {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("severity: got %s, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected kube_privileged finding")
	}
}

func TestKubeRunAsRoot(t *testing.T) {
	uid := int64(0)
	manifests := []collect.KubeManifest{{
		Path: "deploy.yaml",
		Kind: "Deployment",
		Name: "ollama",
		Containers: []collect.KubeContainer{{
			Name:          "ollama",
			RunAsRoot:     true,
			RunAsRootLine: 20,
			RunAsUser:     &uid,
		}},
	}}
	fs := kubeFindings(manifests)
	found := false
	for _, f := range fs {
		if f.ID == "kube_run_as_root" {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("severity: got %s, want HIGH", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected kube_run_as_root finding")
	}
}

func TestKubeHostNetwork(t *testing.T) {
	manifests := []collect.KubeManifest{{
		Path:            "deploy.yaml",
		Kind:            "Deployment",
		Name:            "ollama",
		HostNetwork:     true,
		HostNetworkLine: 12,
	}}
	fs := kubeFindings(manifests)
	found := false
	for _, f := range fs {
		if f.ID == "kube_host_network" {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("severity: got %s, want HIGH", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected kube_host_network finding")
	}
}

func TestKubeHostPathSensitive(t *testing.T) {
	manifests := []collect.KubeManifest{{
		Path: "deploy.yaml",
		Kind: "Deployment",
		Name: "ollama",
		Containers: []collect.KubeContainer{{
			Name: "ollama",
			HostPathMounts: []collect.KubeHostPathMount{{
				HostPath:  "/var/run/docker.sock",
				MountPath: "/var/run/docker.sock",
				Line:      25,
			}},
		}},
	}}
	fs := kubeFindings(manifests)
	found := false
	for _, f := range fs {
		if f.ID == "kube_host_path" {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("docker.sock hostPath should be CRITICAL, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected kube_host_path finding for docker.sock")
	}
}

func TestKubeHostPathNonSensitive(t *testing.T) {
	manifests := []collect.KubeManifest{{
		Path: "deploy.yaml",
		Kind: "Deployment",
		Name: "ollama",
		Containers: []collect.KubeContainer{{
			Name: "ollama",
			HostPathMounts: []collect.KubeHostPathMount{{
				HostPath:  "/data/models",
				MountPath: "/models",
				Line:      25,
			}},
		}},
	}}
	fs := kubeFindings(manifests)
	found := false
	for _, f := range fs {
		if f.ID == "kube_host_path" {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("non-sensitive writable hostPath should be HIGH, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected kube_host_path finding")
	}
}

func TestKubeHostPathReadOnly(t *testing.T) {
	manifests := []collect.KubeManifest{{
		Path: "deploy.yaml",
		Kind: "Deployment",
		Name: "ollama",
		Containers: []collect.KubeContainer{{
			Name: "ollama",
			HostPathMounts: []collect.KubeHostPathMount{{
				HostPath:  "/data/models",
				MountPath: "/models",
				ReadOnly:  true,
				Line:      25,
			}},
		}},
	}}
	fs := kubeFindings(manifests)
	found := false
	for _, f := range fs {
		if f.ID == "kube_host_path" {
			found = true
			if f.Severity != SeverityMedium {
				t.Errorf("read-only non-sensitive hostPath should be MEDIUM, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected kube_host_path finding")
	}
}

func TestKubeStackIntegration(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "kube-stack"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := collect.WalkAndCollect(dir)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(c.KubeManifests) == 0 {
		t.Fatal("expected Kubernetes manifests to be collected from testdata/kube-stack")
	}
	fs := Evaluate(c)

	seen := map[string]bool{}
	for _, f := range fs {
		seen[f.ID] = true
	}

	want := []string{
		"kube_exposed_service", "kube_privileged", "kube_run_as_root",
		"kube_host_network", "kube_host_path",
	}
	for _, id := range want {
		if !seen[id] {
			t.Errorf("expected rule %q to fire on kube-stack fixture", id)
		}
	}
}
