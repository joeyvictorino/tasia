package kafkaaudit

import (
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func makeCollected(services ...compose.Service) *collect.Collected {
	return &collect.Collected{
		Root: "/test",
		ComposeFiles: []compose.ComposeFile{
			{Path: "docker-compose.yml", Services: services},
		},
	}
}

func TestKafkaPlaintextListener(t *testing.T) {
	svc := compose.Service{
		Name:  "kafka",
		Image: "confluentinc/cp-kafka:7.0",
		Environment: []string{
			"KAFKA_LISTENERS=PLAINTEXT://:9092",
			"KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka:9092",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "plaintext_listener" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected plaintext_listener finding")
	}
}

func TestKafkaMissingSASL(t *testing.T) {
	svc := compose.Service{
		Name:        "kafka",
		Image:       "bitnami/kafka:3.4",
		Environment: []string{"KAFKA_LISTENERS=SSL://:9093"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_sasl" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_sasl finding")
	}
}

func TestKafkaWithSASL(t *testing.T) {
	svc := compose.Service{
		Name:  "kafka",
		Image: "confluentinc/cp-kafka:7.0",
		Environment: []string{
			"KAFKA_SASL_MECHANISM=PLAIN",
			"KAFKA_SSL_KEYSTORE_LOCATION=/etc/kafka/keystore.jks",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_sasl" {
				t.Error("should not flag missing_sasl when SASL is configured")
			}
		}
	}
}

func TestKafkaMissingSSL(t *testing.T) {
	svc := compose.Service{
		Name:        "kafka",
		Image:       "wurstmeister/kafka",
		Environment: []string{"KAFKA_SASL_ENABLED_MECHANISMS=SCRAM-SHA-256"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_ssl" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected missing_ssl finding")
	}
}

func TestKafkaWithSSL(t *testing.T) {
	svc := compose.Service{
		Name:  "kafka",
		Image: "bitnami/kafka:3.4",
		Environment: []string{
			"KAFKA_SASL_MECHANISM=PLAIN",
			"KAFKA_SSL_KEYSTORE_LOCATION=/certs/keystore.jks",
			"KAFKA_SSL_TRUSTSTORE_LOCATION=/certs/truststore.jks",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "missing_ssl" {
				t.Error("should not flag missing_ssl when SSL is configured")
			}
		}
	}
}

func TestKafkaExposedBrokerPort(t *testing.T) {
	svc := compose.Service{
		Name:  "kafka",
		Image: "confluentinc/cp-kafka:7.0",
		Ports: []compose.PortMapping{
			{HostPort: 9092, TargetPort: 9092, Raw: "9092:9092"},
		},
		Environment: []string{
			"KAFKA_SASL_MECHANISM=PLAIN",
			"KAFKA_SSL_KEYSTORE_LOCATION=/certs/key.jks",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_broker_port" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected exposed_broker_port finding")
	}
}

func TestKafkaLocalhostPort(t *testing.T) {
	svc := compose.Service{
		Name:  "kafka",
		Image: "confluentinc/cp-kafka:7.0",
		Ports: []compose.PortMapping{
			{HostPort: 9092, TargetPort: 9092, Raw: "127.0.0.1:9092:9092", HostIP: "127.0.0.1"},
		},
		Environment: []string{
			"KAFKA_SASL_MECHANISM=PLAIN",
			"KAFKA_SSL_KEYSTORE_LOCATION=/certs/key.jks",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_broker_port" {
				t.Error("should not flag port bound to localhost")
			}
		}
	}
}

func TestKafkaDefaultCredentials(t *testing.T) {
	svc := compose.Service{
		Name:  "kafka",
		Image: "confluentinc/cp-kafka:7.0",
		Environment: []string{
			"KAFKA_SASL_MECHANISM=PLAIN",
			"KAFKA_SSL_KEYSTORE_LOCATION=/certs/key.jks",
			"KAFKA_OPTS=-Djava.security.auth.login.config=/etc/kafka/jaas.conf admin:admin",
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "default_credentials" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected default_credentials finding")
	}
}

func TestZookeeperUnprotected(t *testing.T) {
	svc := compose.Service{
		Name:        "zookeeper",
		Image:       "bitnami/zookeeper:3.8",
		Environment: []string{"ZOO_PORT=2181"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unprotected_zk" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected unprotected_zk finding")
	}
}

func TestZookeeperWithAuth(t *testing.T) {
	svc := compose.Service{
		Name:  "zookeeper",
		Image: "bitnami/zookeeper:3.8",
		Environment: []string{
			"ZOO_ENABLE_AUTH=yes",
			"ZOO_SERVER_USERS=admin",
		},
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "unprotected_zk" {
				t.Error("should not flag when auth is configured")
			}
		}
	}
}

func TestZookeeperExposedPort(t *testing.T) {
	svc := compose.Service{
		Name:  "zookeeper",
		Image: "wurstmeister/zookeeper",
		Ports: []compose.PortMapping{
			{HostPort: 2181, TargetPort: 2181, Raw: "2181:2181"},
		},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "exposed_broker_port" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected exposed_broker_port for ZooKeeper")
	}
}

func TestNonKafkaService(t *testing.T) {
	svc := compose.Service{
		Name:  "nginx",
		Image: "nginx:latest",
	}
	r := Analyze(makeCollected(svc))
	for _, sr := range r.Services {
		if len(sr.Findings) > 0 {
			t.Error("non-kafka service should have no findings")
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	svc := compose.Service{
		Name:  "kafka",
		Image: "confluentinc/cp-kafka:7.0",
		Ports: []compose.PortMapping{
			{HostPort: 9092, TargetPort: 9092, Raw: "9092:9092"},
		},
		Environment: []string{
			"KAFKA_LISTENERS=PLAINTEXT://:9092",
		},
	}
	r := Analyze(makeCollected(svc))
	if r.Summary.TotalServices != 1 {
		t.Errorf("expected 1 service, got %d", r.Summary.TotalServices)
	}
	if r.Summary.PlaintextListeners != 1 {
		t.Errorf("expected 1 plaintext, got %d", r.Summary.PlaintextListeners)
	}
	if r.Summary.MissingSASL != 1 {
		t.Errorf("expected 1 missing sasl, got %d", r.Summary.MissingSASL)
	}
	if r.Summary.MissingSSL != 1 {
		t.Errorf("expected 1 missing ssl, got %d", r.Summary.MissingSSL)
	}
	if r.Summary.ExposedBrokerPorts != 1 {
		t.Errorf("expected 1 exposed port, got %d", r.Summary.ExposedBrokerPorts)
	}
}

func TestFormatTextOutput(t *testing.T) {
	svc := compose.Service{
		Name:  "kafka",
		Image: "confluentinc/cp-kafka:7.0",
		Environment: []string{
			"KAFKA_LISTENERS=PLAINTEXT://:9092",
		},
	}
	r := Analyze(makeCollected(svc))
	text := FormatText(r)
	if !strings.Contains(text, "Kafka Broker Security Audit") {
		t.Error("expected header in output")
	}
	if !strings.Contains(text, "plaintext") || !strings.Contains(text, "PLAINTEXT") {
		t.Error("expected plaintext mention in output")
	}
}

func TestFormatTextEmpty(t *testing.T) {
	r := Analyze(&collect.Collected{Root: "/empty"})
	text := FormatText(r)
	if !strings.Contains(text, "0 services") {
		t.Error("expected zero services in empty report")
	}
}

func TestMultipleKafkaServices(t *testing.T) {
	svc1 := compose.Service{
		Name:        "kafka1",
		Image:       "confluentinc/cp-kafka:7.0",
		Environment: []string{"KAFKA_LISTENERS=PLAINTEXT://:9092"},
	}
	svc2 := compose.Service{
		Name:  "kafka2",
		Image: "bitnami/kafka:3.4",
		Environment: []string{
			"KAFKA_SASL_MECHANISM=PLAIN",
			"KAFKA_SSL_KEYSTORE_LOCATION=/certs/key.jks",
		},
	}
	r := Analyze(makeCollected(svc1, svc2))
	if r.Summary.TotalServices != 2 {
		t.Errorf("expected 2 services, got %d", r.Summary.TotalServices)
	}
	if r.Summary.PlaintextListeners != 1 {
		t.Errorf("expected 1 plaintext, got %d", r.Summary.PlaintextListeners)
	}
}

func TestRedpandaDetection(t *testing.T) {
	svc := compose.Service{
		Name:        "redpanda",
		Image:       "vectorized/redpanda:latest",
		Environment: []string{"KAFKA_LISTENERS=PLAINTEXT://:9092"},
	}
	r := Analyze(makeCollected(svc))
	found := false
	for _, sr := range r.Services {
		for _, f := range sr.Findings {
			if f.Rule == "plaintext_listener" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected redpanda to be detected as kafka-like")
	}
}

func TestReportPath(t *testing.T) {
	c := &collect.Collected{Root: "/my/project"}
	r := Analyze(c)
	if r.Path != "/my/project" {
		t.Errorf("expected path /my/project, got %s", r.Path)
	}
}

func TestIsKafkaImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"confluentinc/cp-kafka:7.0", true},
		{"bitnami/kafka:3.4", true},
		{"wurstmeister/kafka", true},
		{"strimzi/strimzi-kafka-operator", true},
		{"nginx:latest", false},
		{"postgres:14", false},
	}
	for _, tt := range tests {
		if got := isKafkaImage(tt.image); got != tt.want {
			t.Errorf("isKafkaImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestIsZookeeperImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"bitnami/zookeeper:3.8", true},
		{"cp-zookeeper:7.0", true},
		{"redis:7", false},
	}
	for _, tt := range tests {
		if got := isZookeeperImage(tt.image); got != tt.want {
			t.Errorf("isZookeeperImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}
