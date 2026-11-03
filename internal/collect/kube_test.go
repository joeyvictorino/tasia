package collect

import (
	"testing"
)

const testDeployment = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ollama
  namespace: ai
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ollama
  template:
    metadata:
      labels:
        app: ollama
    spec:
      hostNetwork: true
      containers:
        - name: ollama
          image: ollama/ollama:latest
          securityContext:
            privileged: true
            runAsUser: 0
          volumeMounts:
            - name: docker-sock
              mountPath: /var/run/docker.sock
      volumes:
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
`

func TestParseKubeDeployment(t *testing.T) {
	manifests, err := ParseKubeYAML("deployment.yaml", testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}
	m := manifests[0]
	if m.Kind != "Deployment" {
		t.Errorf("kind: got %q, want Deployment", m.Kind)
	}
	if m.Name != "ollama" {
		t.Errorf("name: got %q, want ollama", m.Name)
	}
	if !m.HostNetwork {
		t.Error("expected hostNetwork=true")
	}
	if len(m.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(m.Containers))
	}
	c := m.Containers[0]
	if !c.Privileged {
		t.Error("expected privileged=true")
	}
	if !c.RunAsRoot {
		t.Error("expected runAsRoot (runAsUser=0)")
	}
	if len(c.HostPathMounts) != 1 {
		t.Fatalf("expected 1 hostPath mount, got %d", len(c.HostPathMounts))
	}
	if c.HostPathMounts[0].HostPath != "/var/run/docker.sock" {
		t.Errorf("hostPath: got %q", c.HostPathMounts[0].HostPath)
	}
}

const testService = `
apiVersion: v1
kind: Service
metadata:
  name: ollama-svc
spec:
  type: LoadBalancer
  ports:
    - port: 11434
      targetPort: 11434
`

func TestParseKubeService(t *testing.T) {
	manifests, err := ParseKubeYAML("service.yaml", testService)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}
	m := manifests[0]
	if m.Kind != "Service" {
		t.Errorf("kind: got %q", m.Kind)
	}
	if m.ServiceType != "LoadBalancer" {
		t.Errorf("type: got %q", m.ServiceType)
	}
	if len(m.ServicePorts) != 1 {
		t.Fatalf("expected 1 port, got %d", len(m.ServicePorts))
	}
	if m.ServicePorts[0].Port != 11434 {
		t.Errorf("port: got %d", m.ServicePorts[0].Port)
	}
}

const testMultiDoc = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
---
apiVersion: v1
kind: Service
metadata:
  name: web-svc
spec:
  type: NodePort
  ports:
    - port: 8080
      nodePort: 30080
`

func TestParseKubeMultiDoc(t *testing.T) {
	manifests, err := ParseKubeYAML("all.yaml", testMultiDoc)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(manifests))
	}
	if manifests[0].Kind != "Deployment" || manifests[1].Kind != "Service" {
		t.Errorf("kinds: %s, %s", manifests[0].Kind, manifests[1].Kind)
	}
}

func TestIsKubeFile(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\n", true},
		{"values.yaml", "replicaCount: 3\n", false},
		{"service.yml", "apiVersion: v1\nkind: Service\n", true},
		{"readme.md", "apiVersion: apps/v1\nkind: Deployment\n", false},
		{"docker-compose.yaml", "version: '3'\nservices:\n", false},
	}
	for _, tc := range cases {
		if got := IsKubeFile(tc.name, tc.content); got != tc.want {
			t.Errorf("IsKubeFile(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestParseKubeRunAsNonRootFalse(t *testing.T) {
	yaml := `
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        runAsNonRoot: false
`
	manifests, err := ParseKubeYAML("pod.yaml", yaml)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}
	c := manifests[0].Containers[0]
	if !c.RunAsRoot {
		t.Error("expected RunAsRoot when runAsNonRoot=false")
	}
}

func TestParseKubeSafeContainer(t *testing.T) {
	yaml := `
apiVersion: v1
kind: Pod
metadata:
  name: safe
spec:
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
`
	manifests, err := ParseKubeYAML("pod.yaml", yaml)
	if err != nil {
		t.Fatal(err)
	}
	c := manifests[0].Containers[0]
	if c.Privileged || c.RunAsRoot {
		t.Error("safe container should have no security findings")
	}
}
