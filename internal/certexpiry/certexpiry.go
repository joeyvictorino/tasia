package certexpiry

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
	SelfSignedCerts    int `json:"self_signed_certs"`
	CertMountNoRotate  int `json:"cert_mount_no_rotate"`
	TLSDisabled        int `json:"tls_disabled"`
	WeakTLSVersion     int `json:"weak_tls_version"`
	CertPathExposed    int `json:"cert_path_exposed"`
	NoCertValidation   int `json:"no_cert_validation"`
}

var selfSignedIndicators = []string{
	"GENERATE_SELF_SIGNED", "SELF_SIGNED=TRUE", "SELF_SIGNED=1",
	"SSL_SELFSIGNED", "TLS_SELF_SIGN",
}

var tlsDisablePatterns = []string{
	"TLS_VERIFY=FALSE", "TLS_VERIFY=0",
	"SSL_VERIFY=FALSE", "SSL_VERIFY=0",
	"NODE_TLS_REJECT_UNAUTHORIZED=0",
	"REQUESTS_CA_BUNDLE=", "CURL_CA_BUNDLE=",
	"PYTHONHTTPSVERIFY=0",
	"GIT_SSL_NO_VERIFY=TRUE", "GIT_SSL_NO_VERIFY=1",
}

var weakTLSPatterns = []string{
	"TLS_MIN_VERSION=1.0", "TLS_MIN_VERSION=1.1",
	"SSL_MIN_PROTOCOL=TLSv1", "SSL_MIN_PROTOCOL=TLSv1.1",
	"MIN_TLS=1.0", "MIN_TLS=1.1",
}

var certPathPrefixes = []string{
	"/etc/ssl/", "/etc/pki/", "/etc/letsencrypt/",
	"/etc/nginx/ssl", "/etc/apache2/ssl",
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

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	for _, env := range svc.Environment {
		envUpper := strings.ToUpper(env)

		for _, pattern := range selfSignedIndicators {
			if strings.Contains(envUpper, pattern) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "self_signed_cert",
					Message: fmt.Sprintf("Service '%s' uses self-signed certificate configuration (%s); not trusted by clients", svc.Name, strings.SplitN(env, "=", 2)[0]),
				})
				break
			}
		}

		for _, pattern := range tlsDisablePatterns {
			if strings.Contains(envUpper, pattern) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "critical",
					Rule:    "tls_validation_disabled",
					Message: fmt.Sprintf("Service '%s' disables TLS certificate validation (%s); vulnerable to MITM attacks", svc.Name, strings.SplitN(env, "=", 2)[0]),
				})
				break
			}
		}

		for _, pattern := range weakTLSPatterns {
			if strings.Contains(envUpper, pattern) {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "weak_tls_version",
					Message: fmt.Sprintf("Service '%s' allows weak TLS version (%s); TLS 1.0/1.1 have known vulnerabilities", svc.Name, env),
				})
				break
			}
		}
	}

	for _, vol := range svc.Volumes {
		parts := strings.SplitN(vol, ":", 2)
		if len(parts) >= 2 {
			src := strings.ToLower(parts[0])
			for _, prefix := range certPathPrefixes {
				if strings.HasPrefix(src, prefix) {
					isRO := strings.Contains(vol, ":ro")
					if !isRO {
						sr.Findings = append(sr.Findings, Finding{
							Level:   "high",
							Rule:    "cert_mount_writable",
							Message: fmt.Sprintf("Service '%s' mounts certificate path %s writable; container can modify TLS certificates", svc.Name, src),
						})
					}
					sr.Findings = append(sr.Findings, Finding{
						Level:   "medium",
						Rule:    "cert_path_exposed",
						Message: fmt.Sprintf("Service '%s' mounts certificate directory %s; ensure rotation and access controls", svc.Name, src),
					})
					break
				}
			}
		}
	}

	for _, cmd := range append(svc.Entrypoint, svc.Command...) {
		cmdLower := strings.ToLower(cmd)
		if strings.Contains(cmdLower, "--insecure") || strings.Contains(cmdLower, "-k") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "insecure_flag",
				Message: fmt.Sprintf("Service '%s' uses --insecure or -k flag; TLS verification bypassed", svc.Name),
			})
		}
		if strings.Contains(cmdLower, "--no-check-certificate") {
			sr.Findings = append(sr.Findings, Finding{
				Level:   "high",
				Rule:    "no_cert_check",
				Message: fmt.Sprintf("Service '%s' uses --no-check-certificate; TLS verification bypassed", svc.Name),
			})
		}
	}

	return sr
}

func summarize(services []ServiceResult) Summary {
	s := Summary{TotalServices: len(services)}
	for _, sr := range services {
		s.TotalFindings += len(sr.Findings)
		for _, f := range sr.Findings {
			switch f.Rule {
			case "self_signed_cert":
				s.SelfSignedCerts++
			case "cert_mount_writable":
				s.CertMountNoRotate++
			case "tls_validation_disabled":
				s.TLSDisabled++
			case "weak_tls_version":
				s.WeakTLSVersion++
			case "cert_path_exposed":
				s.CertPathExposed++
			case "insecure_flag", "no_cert_check":
				s.NoCertValidation++
			}
		}
	}
	return s
}
