package kafkaaudit

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

type ServiceResult struct {
	Service  string    `json:"service"`
	File     string    `json:"file"`
	Findings []Finding `json:"findings"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

type Summary struct {
	TotalServices      int `json:"total_services"`
	TotalFindings      int `json:"total_findings"`
	PlaintextListeners int `json:"plaintext_listeners"`
	MissingSASL        int `json:"missing_sasl"`
	MissingSSL         int `json:"missing_ssl"`
	ExposedBrokerPorts int `json:"exposed_broker_ports"`
	UnprotectedZK      int `json:"unprotected_zk"`
	DefaultCredentials int `json:"default_credentials"`
}

var kafkaImages = []string{
	"kafka", "confluent", "cp-kafka", "bitnami/kafka",
	"wurstmeister/kafka", "strimzi", "redpanda",
}

var zookeeperImages = []string{
	"zookeeper", "cp-zookeeper", "bitnami/zookeeper",
	"wurstmeister/zookeeper",
}

func isKafkaImage(image string) bool {
	lower := strings.ToLower(image)
	for _, ki := range kafkaImages {
		if strings.Contains(lower, ki) {
			return true
		}
	}
	return false
}

func isZookeeperImage(image string) bool {
	lower := strings.ToLower(image)
	for _, zi := range zookeeperImages {
		if strings.Contains(lower, zi) {
			return true
		}
	}
	return false
}

var plaintextVars = []string{
	"KAFKA_LISTENERS",
	"KAFKA_ADVERTISED_LISTENERS",
	"KAFKA_CFG_LISTENERS",
	"KAFKA_CFG_ADVERTISED_LISTENERS",
	"KAFKA_LISTENER_SECURITY_PROTOCOL_MAP",
}

var saslVars = []string{
	"KAFKA_SASL_MECHANISM",
	"KAFKA_OPTS",
	"KAFKA_CFG_SASL_ENABLED_MECHANISMS",
	"KAFKA_SASL_ENABLED_MECHANISMS",
	"KAFKA_INTER_BROKER_LISTENER_NAME",
}

var sslVars = []string{
	"KAFKA_SSL_KEYSTORE_LOCATION",
	"KAFKA_SSL_TRUSTSTORE_LOCATION",
	"KAFKA_SSL_KEY_PASSWORD",
	"KAFKA_CFG_SSL_KEYSTORE_LOCATION",
	"KAFKA_SECURITY_INTER_BROKER_PROTOCOL",
}

var defaultCreds = []string{
	"admin:admin", "kafka:kafka", "admin:password",
	"kafka:password", "admin:secret",
}

func getEnvValue(envs []string, key string) string {
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], key) {
			return parts[1]
		}
	}
	return ""
}

func hasEnvKey(envs []string, key string) bool {
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) >= 1 && strings.EqualFold(parts[0], key) {
			return true
		}
	}
	return false
}

func containsPlaintext(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "plaintext")
}

func hasSASLConfig(envs []string) bool {
	for _, k := range saslVars {
		if hasEnvKey(envs, k) {
			return true
		}
	}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "sasl") {
			return true
		}
	}
	return false
}

func hasSSLConfig(envs []string) bool {
	for _, k := range sslVars {
		if hasEnvKey(envs, k) {
			return true
		}
	}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "ssl") || strings.Contains(lower, "tls") {
			return true
		}
	}
	return false
}

func hasDefaultCredentials(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		for _, cred := range defaultCreds {
			if strings.Contains(lower, cred) {
				return true
			}
		}
	}
	return false
}

func isKafkaBrokerPort(port compose.PortMapping) bool {
	return port.TargetPort == 9092 || port.TargetPort == 9093 || port.TargetPort == 9094 || port.TargetPort == 29092
}

func isZookeeperPort(port compose.PortMapping) bool {
	return port.TargetPort == 2181 || port.TargetPort == 2888 || port.TargetPort == 3888
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	isKafka := isKafkaImage(svc.Image)
	isZK := isZookeeperImage(svc.Image)

	if !isKafka && !isZK {
		return sr
	}

	if isKafka {
		hasPlaintext := false
		for _, pv := range plaintextVars {
			val := getEnvValue(svc.Environment, pv)
			if val != "" && containsPlaintext(val) {
				hasPlaintext = true
				break
			}
		}

		if hasPlaintext {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "plaintext_listener",
				Message: fmt.Sprintf("Service '%s' configures Kafka with PLAINTEXT listeners; data is transmitted unencrypted", svc.Name),
			})
		}

		if !hasSASLConfig(svc.Environment) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "missing_sasl",
				Message: fmt.Sprintf("Service '%s' Kafka broker has no SASL authentication configured; any client can connect", svc.Name),
			})
		}

		if !hasSSLConfig(svc.Environment) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "missing_ssl",
				Message: fmt.Sprintf("Service '%s' Kafka broker has no SSL/TLS configuration; traffic is unencrypted", svc.Name),
			})
		}

		for _, port := range svc.Ports {
			if isKafkaBrokerPort(port) && port.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "exposed_broker_port",
					Message: fmt.Sprintf("Service '%s' exposes Kafka broker port %d on all interfaces", svc.Name, port.TargetPort),
				})
			}
		}

		if hasDefaultCredentials(svc.Environment) {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "critical",
				Rule:    "default_credentials",
				Message: fmt.Sprintf("Service '%s' appears to use default credentials for Kafka authentication", svc.Name),
			})
		}
	}

	if isZK {
		hasAuth := false
		for _, e := range svc.Environment {
			lower := strings.ToLower(e)
			if strings.Contains(lower, "auth") || strings.Contains(lower, "sasl") || strings.Contains(lower, "acl") {
				hasAuth = true
				break
			}
		}

		if !hasAuth {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "unprotected_zk",
				Message: fmt.Sprintf("Service '%s' ZooKeeper has no authentication configured; Kafka metadata is exposed", svc.Name),
			})
		}

		for _, port := range svc.Ports {
			if isZookeeperPort(port) && port.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "exposed_broker_port",
					Message: fmt.Sprintf("Service '%s' exposes ZooKeeper port %d on all interfaces", svc.Name, port.TargetPort),
				})
			}
		}
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			r.Services = append(r.Services, sr)
		}
	}
	r.Summary = summarize(r.Services)
	return r
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		for _, f := range sr.Findings {
			s.TotalFindings++
			switch f.Rule {
			case "plaintext_listener":
				s.PlaintextListeners++
			case "missing_sasl":
				s.MissingSASL++
			case "missing_ssl":
				s.MissingSSL++
			case "exposed_broker_port":
				s.ExposedBrokerPorts++
			case "unprotected_zk":
				s.UnprotectedZK++
			case "default_credentials":
				s.DefaultCredentials++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Kafka Broker Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Plaintext listeners:    %d\n", r.Summary.PlaintextListeners)
	fmt.Fprintf(&b, "  Missing SASL auth:      %d\n", r.Summary.MissingSASL)
	fmt.Fprintf(&b, "  Missing SSL/TLS:        %d\n", r.Summary.MissingSSL)
	fmt.Fprintf(&b, "  Exposed broker ports:   %d\n", r.Summary.ExposedBrokerPorts)
	fmt.Fprintf(&b, "  Unprotected ZooKeeper:  %d\n", r.Summary.UnprotectedZK)
	fmt.Fprintf(&b, "  Default credentials:    %d\n\n", r.Summary.DefaultCredentials)
	for _, sr := range r.Services {
		fmt.Fprintf(&b, "  %-30s\n", sr.Service)
		fmt.Fprintf(&b, "    file: %s\n", sr.File)
		if len(sr.Findings) == 0 {
			fmt.Fprintf(&b, "    (no findings)\n")
		}
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Level, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
