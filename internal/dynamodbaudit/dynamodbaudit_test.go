package dynamodbaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, env []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports}
}

func svcCmd(name, image string, env []string, ports []compose.PortMapping, cmd []string) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports, Command: cmd}
}

func allIf(target int) compose.PortMapping {
	return compose.PortMapping{HostPort: target, TargetPort: target, HostIP: "0.0.0.0"}
}

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func colPath(path string, svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: path, ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func TestIsDynamoDBImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"amazon/dynamodb-local:latest", true},
		{"amazon/dynamodb-local:2.0.0", true},
		{"dynamodb-local:latest", true},
		{"instructure/dynamo-local-admin:latest", true},
		{"deangiberson/aws-dynamodb-local:latest", true},
		{"nginx:latest", false},
		{"AMAZON/DYNAMODB-LOCAL:latest", true},
	}
	for _, tt := range tests {
		if got := isDynamoDBImage(tt.image); got != tt.want {
			t.Errorf("isDynamoDBImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestNoAuth(t *testing.T) {
	r := Analyze(col(svc("ddb", "amazon/dynamodb-local:latest", nil, nil)))
	if r.Summary.NoAuth == 0 {
		t.Error("expected dynamodb_no_auth finding when no credentials set")
	}
}

func TestAuthSet(t *testing.T) {
	r := Analyze(col(svc("ddb", "amazon/dynamodb-local:latest",
		[]string{"AWS_ACCESS_KEY_ID=test", "AWS_SECRET_ACCESS_KEY=test"}, nil)))
	if r.Summary.NoAuth != 0 {
		t.Error("expected no dynamodb_no_auth finding when credentials set")
	}
}

func TestExposedPort(t *testing.T) {
	r := Analyze(col(svc("ddb", "amazon/dynamodb-local:latest", nil, []compose.PortMapping{allIf(8000)})))
	if r.Summary.ExposedPort == 0 {
		t.Error("expected dynamodb_exposed_port finding for 8000")
	}
}

func TestDefaultRegion(t *testing.T) {
	r := Analyze(col(svc("ddb", "amazon/dynamodb-local:latest", nil, nil)))
	if r.Summary.DefaultRegion == 0 {
		t.Error("expected dynamodb_default_region finding when no region set")
	}
}

func TestRegionSet(t *testing.T) {
	r := Analyze(col(svc("ddb", "amazon/dynamodb-local:latest",
		[]string{"AWS_DEFAULT_REGION=us-east-1"}, nil)))
	if r.Summary.DefaultRegion != 0 {
		t.Error("expected no default_region finding when region set")
	}
}

func TestSharedDB(t *testing.T) {
	r := Analyze(col(svcCmd("ddb", "amazon/dynamodb-local:latest", nil, nil,
		[]string{"-jar", "DynamoDBLocal.jar", "-sharedDb"})))
	if r.Summary.SharedDB == 0 {
		t.Error("expected dynamodb_shared_db finding")
	}
}

func TestNoSharedDB(t *testing.T) {
	r := Analyze(col(svcCmd("ddb", "amazon/dynamodb-local:latest", nil, nil,
		[]string{"-jar", "DynamoDBLocal.jar"})))
	if r.Summary.SharedDB != 0 {
		t.Error("expected no shared_db finding without flag")
	}
}

func TestInMemory(t *testing.T) {
	r := Analyze(col(svcCmd("ddb", "amazon/dynamodb-local:latest", nil, nil,
		[]string{"-jar", "DynamoDBLocal.jar", "-inMemory"})))
	if r.Summary.InMemoryStorage == 0 {
		t.Error("expected dynamodb_in_memory finding")
	}
}

func TestNoInMemory(t *testing.T) {
	r := Analyze(col(svcCmd("ddb", "amazon/dynamodb-local:latest", nil, nil,
		[]string{"-jar", "DynamoDBLocal.jar"})))
	if r.Summary.InMemoryStorage != 0 {
		t.Error("expected no in_memory finding without flag")
	}
}

func TestNonDynamoDBSkipped(t *testing.T) {
	r := Analyze(col(svc("web", "nginx:latest", nil, nil)))
	if len(r.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(r.Services))
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(colPath("/test", svc("ddb", "amazon/dynamodb-local:latest", nil, nil)))
	text := FormatText(r)
	if !strings.Contains(text, "DynamoDB Local Security Audit") {
		t.Error("missing title")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	text := FormatText(r)
	if !strings.Contains(text, "No DynamoDB Local services found") {
		t.Error("expected empty message")
	}
}

func TestEmptyCollection(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	if len(r.Services) != 0 {
		t.Error("expected empty report")
	}
}

func TestReportPath(t *testing.T) {
	r := Analyze(colPath("/mydir"))
	if r.Path != "/mydir" {
		t.Errorf("expected /mydir, got %s", r.Path)
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(col(
		svc("ddb1", "amazon/dynamodb-local:latest", nil, nil),
		svc("ddb2", "dynamodb-local:latest", nil, nil),
	))
	if len(r.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(r.Services))
	}
}
