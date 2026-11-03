package etcdaudit

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
	TotalServices   int `json:"total_services"`
	TotalFindings   int `json:"total_findings"`
	MissingClientTLS int `json:"missing_client_tls"`
	MissingPeerTLS  int `json:"missing_peer_tls"`
	MissingAuth     int `json:"missing_auth"`
	ExposedPorts    int `json:"exposed_ports"`
	DefaultCreds    int `json:"default_credentials"`
	InsecureTransport int `json:"insecure_transport"`
}

var etcdImages = []string{
	"etcd", "bitnami/etcd", "quay.io/coreos/etcd",
	"gcr.io/etcd-development/etcd", "k8s.gcr.io/etcd",
	"registry.k8s.io/etcd",
}

func isEtcdImage(image string) bool {
	lower := strings.ToLower(image)
	for _, ei := range etcdImages {
		if strings.Contains(lower, ei) {
			return true
		}
	}
	return false
}

func hasEnvContaining(envs []string, substr string) bool {
	lower := strings.ToLower(substr)
	for _, e := range envs {
		if strings.Contains(strings.ToLower(e), lower) {
			return true
		}
	}
	return false
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

func isEtcdPort(port compose.PortMapping) bool {
	return port.TargetPort == 2379 || port.TargetPort == 2380 || port.TargetPort == 4001
}

func hasClientTLS(envs []string) bool {
	if hasEnvContaining(envs, "ETCD_CERT_FILE") || hasEnvContaining(envs, "ETCD_KEY_FILE") {
		return true
	}
	if hasEnvContaining(envs, "ETCD_CLIENT_CERT_AUTH") {
		return true
	}
	if hasEnvContaining(envs, "ETCD_AUTO_TLS") {
		val := getEnvValue(envs, "ETCD_AUTO_TLS")
		if strings.EqualFold(val, "true") {
			return true
		}
	}
	if hasEnvContaining(envs, "--cert-file") || hasEnvContaining(envs, "--key-file") {
		return true
	}
	return false
}

func hasPeerTLS(envs []string) bool {
	if hasEnvContaining(envs, "ETCD_PEER_CERT_FILE") || hasEnvContaining(envs, "ETCD_PEER_KEY_FILE") {
		return true
	}
	if hasEnvContaining(envs, "ETCD_PEER_CLIENT_CERT_AUTH") {
		return true
	}
	if hasEnvContaining(envs, "ETCD_PEER_AUTO_TLS") {
		val := getEnvValue(envs, "ETCD_PEER_AUTO_TLS")
		if strings.EqualFold(val, "true") {
			return true
		}
	}
	if hasEnvContaining(envs, "--peer-cert-file") || hasEnvContaining(envs, "--peer-key-file") {
		return true
	}
	return false
}

func hasAuth(envs []string) bool {
	if hasEnvContaining(envs, "ETCD_AUTH_TOKEN") {
		return true
	}
	if hasEnvContaining(envs, "ETCDCTL_USER") || hasEnvContaining(envs, "ETCD_ROOT_PASSWORD") {
		return true
	}
	if hasEnvContaining(envs, "ALLOW_NONE_AUTHENTICATION=no") {
		return true
	}
	return false
}

func hasInsecureTransport(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "http://") && (strings.Contains(lower, "advertise") || strings.Contains(lower, "listen") || strings.Contains(lower, "initial")) {
			return true
		}
	}
	return false
}

var defaultCreds = []string{
	"root:root", "admin:admin", "etcd:etcd",
	"admin:password", "admin:secret",
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

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isEtcdImage(svc.Image) {
		return sr
	}

	if !hasClientTLS(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "missing_client_tls",
			Message: fmt.Sprintf("Service '%s' etcd has no client TLS configured; client-server traffic is unencrypted", svc.Name),
		})
	}

	if !hasPeerTLS(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "missing_peer_tls",
			Message: fmt.Sprintf("Service '%s' etcd has no peer TLS configured; inter-node traffic is unencrypted", svc.Name),
		})
	}

	if !hasAuth(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "missing_auth",
			Message: fmt.Sprintf("Service '%s' etcd has no authentication configured; any client can read/write cluster data", svc.Name),
		})
	}

	for _, port := range svc.Ports {
		if isEtcdPort(port) && port.IsAllInterfaces() {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "exposed_port",
				Message: fmt.Sprintf("Service '%s' exposes etcd port %d on all interfaces", svc.Name, port.TargetPort),
			})
		}
	}

	if hasDefaultCredentials(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "default_credentials",
			Message: fmt.Sprintf("Service '%s' appears to use default credentials for etcd authentication", svc.Name),
		})
	}

	if hasInsecureTransport(svc.Environment) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "insecure_transport",
			Message: fmt.Sprintf("Service '%s' etcd uses http:// URLs for advertise/listen endpoints instead of https://", svc.Name),
		})
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
			case "missing_client_tls":
				s.MissingClientTLS++
			case "missing_peer_tls":
				s.MissingPeerTLS++
			case "missing_auth":
				s.MissingAuth++
			case "exposed_port":
				s.ExposedPorts++
			case "default_credentials":
				s.DefaultCreds++
			case "insecure_transport":
				s.InsecureTransport++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "etcd Security Audit (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  Missing client TLS:       %d\n", r.Summary.MissingClientTLS)
	fmt.Fprintf(&b, "  Missing peer TLS:         %d\n", r.Summary.MissingPeerTLS)
	fmt.Fprintf(&b, "  Missing authentication:   %d\n", r.Summary.MissingAuth)
	fmt.Fprintf(&b, "  Exposed ports:            %d\n", r.Summary.ExposedPorts)
	fmt.Fprintf(&b, "  Default credentials:      %d\n", r.Summary.DefaultCreds)
	fmt.Fprintf(&b, "  Insecure transport:       %d\n\n", r.Summary.InsecureTransport)

	for _, sr := range r.Services {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s (%s)\n", sr.Service, sr.File)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", strings.ToUpper(f.Level), f.Rule, f.Message)
		}
		b.WriteString("\n")
	}
	return b.String()
}
