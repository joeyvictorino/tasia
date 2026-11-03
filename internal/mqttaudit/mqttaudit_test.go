package mqttaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func mkCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		ComposeFiles: []compose.File{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func svc(name string, opts ...func(*compose.Service)) compose.Service {
	s := compose.Service{Name: name}
	for _, o := range opts {
		o(&s)
	}
	return s
}

func withEnv(envs ...string) func(*compose.Service) {
	return func(s *compose.Service) {
		s.Environment = append(s.Environment, envs...)
	}
}

func withImage(img string) func(*compose.Service) {
	return func(s *compose.Service) {
		s.Image = img
	}
}

func withPorts(ports ...string) func(*compose.Service) {
	return func(s *compose.Service) {
		for _, p := range ports {
			s.Ports = append(s.Ports, compose.PortMapping{Raw: p})
		}
	}
}

func withVolumes(vols ...string) func(*compose.Service) {
	return func(s *compose.Service) {
		s.Volumes = append(s.Volumes, vols...)
	}
}

func findRule(results []ServiceResult, ruleID string) *Finding {
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Rule == ruleID {
				return &f
			}
		}
	}
	return nil
}

func countRule(results []ServiceResult, ruleID string) int {
	n := 0
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Rule == ruleID {
				n++
			}
		}
	}
	return n
}

func TestAnonymousAccessEnabled(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"), withEnv("MQTT_ALLOW_ANONYMOUS=true")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-001") == nil {
		t.Fatal("expected MQTT-001 for anonymous access")
	}
}

func TestAnonymousAccessDisabled(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"), withEnv("MQTT_ALLOW_ANONYMOUS=false")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-001") != nil {
		t.Fatal("unexpected MQTT-001 when anonymous is disabled")
	}
}

func TestUnencryptedPort(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"), withPorts("1883:1883")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-002") == nil {
		t.Fatal("expected MQTT-002 for unencrypted port")
	}
}

func TestEncryptedPortPresent(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"), withPorts("1883:1883", "8883:8883")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-002") != nil {
		t.Fatal("unexpected MQTT-002 when TLS port present")
	}
}

func TestDefaultCredentialsMosquitto(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto:latest")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-003") == nil {
		t.Fatal("expected MQTT-003 for mosquitto without auth")
	}
}

func TestCredentialsConfigured(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"), withEnv("MQTT_USERNAME=admin", "MQTT_PASSWORD=secret")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-003") != nil {
		t.Fatal("unexpected MQTT-003 when credentials configured")
	}
}

func TestPasswordVolumeMount(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"), withVolumes("./config/password_file:/mosquitto/config/password_file")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-003") != nil {
		t.Fatal("unexpected MQTT-003 when password file mounted")
	}
}

func TestNoACL(t *testing.T) {
	c := mkCollected(svc("broker", withImage("emqx/emqx")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-004") == nil {
		t.Fatal("expected MQTT-004 for missing ACL")
	}
}

func TestACLConfigured(t *testing.T) {
	c := mkCollected(svc("broker", withImage("emqx/emqx"), withEnv("MQTT_ACL_FILE=/etc/acl.conf")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-004") != nil {
		t.Fatal("unexpected MQTT-004 when ACL configured")
	}
}

func TestACLVolumeMount(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"), withVolumes("./config/acl.conf:/mosquitto/config/acl.conf")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-004") != nil {
		t.Fatal("unexpected MQTT-004 when ACL volume mounted")
	}
}

func TestWebSocketNoTLS(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"), withPorts("9001:9001")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-005") == nil {
		t.Fatal("expected MQTT-005 for WebSocket without TLS")
	}
}

func TestWebSocketWithTLS(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"), withPorts("9001:9001"), withEnv("WS_TLS=true")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-005") != nil {
		t.Fatal("unexpected MQTT-005 when WS_TLS configured")
	}
}

func TestWildcardAllowed(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"), withEnv("MQTT_ALLOW_WILDCARD=true")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-006") == nil {
		t.Fatal("expected MQTT-006 for wildcard allowed")
	}
}

func TestNonMQTTServiceIgnored(t *testing.T) {
	c := mkCollected(svc("postgres", withImage("postgres:15")))
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestSummaryAffectedCount(t *testing.T) {
	c := mkCollected(
		svc("broker", withImage("eclipse-mosquitto"), withEnv("MQTT_ALLOW_ANONYMOUS=true")),
		svc("db", withImage("postgres:15")),
	)
	r := Analyze(c)
	if r.Summary.AffectedServices != 1 {
		t.Fatalf("expected 1 affected, got %d", r.Summary.AffectedServices)
	}
}

func TestFormatTextContainsHeader(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"), withEnv("MQTT_ALLOW_ANONYMOUS=true")))
	r := Analyze(c)
	text := FormatText(r)
	if !strings.Contains(text, "MQTT Broker") {
		t.Fatal("expected header in text output")
	}
}

func TestFormatJSONValid(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto")))
	r := Analyze(c)
	j := FormatJSON(r)
	if !strings.Contains(j, "Results") {
		t.Fatal("expected Results in JSON")
	}
}

func TestMultipleRulesOnOneService(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"),
		withEnv("MQTT_ALLOW_ANONYMOUS=true", "MQTT_ALLOW_WILDCARD=true"),
		withPorts("1883:1883", "9001:9001"),
	))
	r := Analyze(c)
	if r.Summary.TotalFindings < 3 {
		t.Fatalf("expected at least 3 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestEMQXDetected(t *testing.T) {
	c := mkCollected(svc("broker", withImage("emqx/emqx:latest")))
	r := Analyze(c)
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for emqx broker")
	}
}

func TestVerneMQDetected(t *testing.T) {
	c := mkCollected(svc("broker", withImage("vernemq/vernemq:latest")))
	r := Analyze(c)
	if r.Summary.TotalFindings == 0 {
		t.Fatal("expected findings for vernemq broker")
	}
}

func TestEmptyCollected(t *testing.T) {
	c := mkCollected()
	r := Analyze(c)
	if r.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings, got %d", r.Summary.TotalFindings)
	}
}

func TestWSEnabledEnv(t *testing.T) {
	c := mkCollected(svc("broker", withImage("eclipse-mosquitto"), withEnv("WS_ENABLED=true")))
	r := Analyze(c)
	if findRule(r.Results, "MQTT-005") == nil {
		t.Fatal("expected MQTT-005 for WS_ENABLED without TLS")
	}
}
