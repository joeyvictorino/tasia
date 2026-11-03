package trustchain

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func svc(name, image string, env []string, ports []compose.PortMapping) compose.Service {
	return compose.Service{Name: name, Image: image, Environment: env, Ports: ports}
}

func svcDeps(name, image string, ports []compose.PortMapping, deps map[string]compose.DependsOnCondition) compose.Service {
	return compose.Service{Name: name, Image: image, Ports: ports, DependsOn: deps}
}

func allIf(target int) compose.PortMapping {
	return compose.PortMapping{HostPort: target, TargetPort: target, HostIP: "0.0.0.0"}
}

func col(svcs ...compose.Service) *collect.Collected {
	return &collect.Collected{Root: ".", ComposeFiles: []compose.File{{Path: "docker-compose.yml", Services: svcs}}}
}

func TestEmptyCollection(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "."})
	if len(r.Nodes) != 0 {
		t.Error("expected empty report")
	}
}

func TestExternalZone(t *testing.T) {
	r := Analyze(col(svc("web", "nginx", nil, []compose.PortMapping{allIf(80)})))
	if len(r.Nodes) != 1 {
		t.Fatal("expected 1 node")
	}
	if r.Nodes[0].Zone != ZoneExternal {
		t.Errorf("expected external zone, got %s", r.Nodes[0].Zone)
	}
	if r.Summary.ExternalCount != 1 {
		t.Errorf("expected external count 1, got %d", r.Summary.ExternalCount)
	}
}

func TestInternalZone(t *testing.T) {
	r := Analyze(col(svc("db", "postgres", nil, nil)))
	if len(r.Nodes) != 1 {
		t.Fatal("expected 1 node")
	}
	if r.Nodes[0].Zone != ZoneInternal {
		t.Errorf("expected internal zone, got %s", r.Nodes[0].Zone)
	}
}

func TestBridgeZone(t *testing.T) {
	r := Analyze(col(
		svcDeps("web", "nginx", []compose.PortMapping{allIf(80)}, map[string]compose.DependsOnCondition{"db": {}}),
		svc("db", "postgres", nil, nil),
	))
	found := false
	for _, n := range r.Nodes {
		if n.Name == "web" && n.Zone == ZoneBridge {
			found = true
		}
	}
	if !found {
		t.Error("expected web to be in bridge zone")
	}
	if r.Summary.BridgeCount != 1 {
		t.Errorf("expected bridge count 1, got %d", r.Summary.BridgeCount)
	}
}

func TestBridgeFinding(t *testing.T) {
	r := Analyze(col(
		svcDeps("proxy", "nginx", []compose.PortMapping{allIf(443)}, map[string]compose.DependsOnCondition{"api": {}}),
		svc("api", "myapp", nil, nil),
	))
	if r.Summary.FindingCount == 0 {
		t.Error("expected trust_bridge finding")
	}
	hasBridge := false
	for _, f := range r.Findings {
		if f.Rule == "trust_bridge" {
			hasBridge = true
		}
	}
	if !hasBridge {
		t.Error("missing trust_bridge rule finding")
	}
}

func TestHostNetworkFinding(t *testing.T) {
	s := svc("app", "myapp", nil, []compose.PortMapping{allIf(8080)})
	s.NetworkMode = "host"
	r := Analyze(col(s))
	hasHostNet := false
	for _, f := range r.Findings {
		if f.Rule == "trust_host_network_exposed" {
			hasHostNet = true
		}
	}
	if !hasHostNet {
		t.Error("expected trust_host_network_exposed finding")
	}
}

func TestMissingDependencyFinding(t *testing.T) {
	r := Analyze(col(
		svcDeps("web", "nginx", nil, map[string]compose.DependsOnCondition{"missing_svc": {}}),
	))
	hasMissing := false
	for _, f := range r.Findings {
		if f.Rule == "trust_missing_dependency" {
			hasMissing = true
		}
	}
	if !hasMissing {
		t.Error("expected trust_missing_dependency finding")
	}
}

func TestMultipleServices(t *testing.T) {
	r := Analyze(col(
		svc("web", "nginx", nil, []compose.PortMapping{allIf(80)}),
		svc("db", "postgres", nil, nil),
		svc("redis", "redis", nil, nil),
	))
	if r.Summary.TotalServices != 3 {
		t.Errorf("expected 3 services, got %d", r.Summary.TotalServices)
	}
}

func TestFormatText(t *testing.T) {
	r := Analyze(col(
		svcDeps("web", "nginx", []compose.PortMapping{allIf(80)}, map[string]compose.DependsOnCondition{"db": {}}),
		svc("db", "postgres", nil, nil),
	))
	text := FormatText(r)
	if !strings.Contains(text, "Trust Chain Analysis") {
		t.Error("missing title")
	}
	if !strings.Contains(text, "bridge") {
		t.Error("missing bridge zone in output")
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/mydir"}
	r := Analyze(c)
	if r.Path != "/mydir" {
		t.Errorf("expected /mydir, got %s", r.Path)
	}
}
