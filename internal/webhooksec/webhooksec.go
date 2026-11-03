package webhooksec

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
	TotalServices          int `json:"total_services"`
	TotalFindings          int `json:"total_findings"`
	NoWebhookSecret        int `json:"no_webhook_secret"`
	InsecureWebhookURL     int `json:"insecure_webhook_url"`
	PublicWebhookNoAuth    int `json:"public_webhook_no_auth"`
	WebhookNoTLS           int `json:"webhook_no_tls"`
	WebhookReplayVuln      int `json:"webhook_replay_vuln"`
}

var webhookImages = []string{
	"webhook", "hookdeck", "svix", "ngrok",
	"smee", "webhook-relay", "hookdoo",
}

var webhookEnvKeys = []string{
	"webhook_url", "webhook_endpoint", "webhook_callback",
	"hook_url", "callback_url", "notify_url",
	"webhook_path", "event_url", "webhook_host",
}

var webhookSecretKeys = []string{
	"webhook_secret", "hook_secret", "signing_secret",
	"webhook_token", "hook_token", "webhook_key",
	"hmac_secret", "signature_key", "webhook_signing",
}

var webhookAuthKeys = []string{
	"webhook_auth", "hook_auth", "webhook_api_key",
	"webhook_bearer", "webhook_password", "hook_api_key",
}

var webhookTimestampKeys = []string{
	"webhook_timestamp_tolerance", "hook_timestamp_check",
	"webhook_replay_protection", "webhook_max_age",
	"signature_timestamp", "hook_replay_guard",
}

func isWebhookService(svc compose.Service) bool {
	lower := strings.ToLower(svc.Image)
	for _, img := range webhookImages {
		if strings.Contains(lower, img) {
			return true
		}
	}
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		for _, k := range webhookEnvKeys {
			if strings.Contains(lower, k) {
				return true
			}
		}
	}
	return false
}

func hasWebhookSecret(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		for _, k := range webhookSecretKeys {
			if strings.Contains(lower, k) {
				return true
			}
		}
	}
	return false
}

func hasWebhookAuth(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		for _, k := range webhookAuthKeys {
			if strings.Contains(lower, k) {
				return true
			}
		}
	}
	return false
}

func hasInsecureWebhookURL(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "http://") {
			for _, k := range webhookEnvKeys {
				if strings.Contains(lower, k) {
					return true
				}
			}
		}
	}
	return false
}

func hasReplayProtection(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		for _, k := range webhookTimestampKeys {
			if strings.Contains(lower, k) {
				return true
			}
		}
	}
	return false
}

func hasPublicPort(svc compose.Service) bool {
	for _, p := range svc.Ports {
		if p.IsAllInterfaces() {
			return true
		}
	}
	return false
}

func hasTLSConfig(svc compose.Service) bool {
	for _, e := range svc.Environment {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "tls_cert") ||
			strings.Contains(lower, "ssl_cert") ||
			strings.Contains(lower, "https_cert") ||
			strings.Contains(lower, "webhook_tls") ||
			strings.Contains(lower, "hook_ssl") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name, File: file}

	if !isWebhookService(svc) {
		return sr
	}

	if !hasWebhookSecret(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "no_webhook_secret",
			Message: fmt.Sprintf("webhook service '%s' has no signing secret configured; incoming webhooks cannot be verified as authentic without HMAC signature validation", svc.Name),
		})
	}

	if hasInsecureWebhookURL(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "insecure_webhook_url",
			Message: fmt.Sprintf("webhook service '%s' uses an HTTP (non-TLS) callback URL; webhook payloads may be intercepted in transit", svc.Name),
		})
	}

	if hasPublicPort(svc) && !hasWebhookAuth(svc) && !hasWebhookSecret(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "public_webhook_no_auth",
			Message: fmt.Sprintf("webhook service '%s' is publicly exposed without authentication; unauthenticated webhook endpoints allow spoofed event injection", svc.Name),
		})
	}

	if hasPublicPort(svc) && !hasTLSConfig(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "webhook_no_tls",
			Message: fmt.Sprintf("webhook service '%s' is publicly exposed without TLS configuration; webhook traffic should be encrypted", svc.Name),
		})
	}

	if !hasReplayProtection(svc) && hasWebhookSecret(svc) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "webhook_replay_vuln",
			Message: fmt.Sprintf("webhook service '%s' has signing configured but no replay protection; signed payloads can be replayed without timestamp validation", svc.Name),
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
			case "no_webhook_secret":
				s.NoWebhookSecret++
			case "insecure_webhook_url":
				s.InsecureWebhookURL++
			case "public_webhook_no_auth":
				s.PublicWebhookNoAuth++
			case "webhook_no_tls":
				s.WebhookNoTLS++
			case "webhook_replay_vuln":
				s.WebhookReplayVuln++
			}
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Webhook Security Analysis (%d services, %d findings)\n\n", r.Summary.TotalServices, r.Summary.TotalFindings)
	fmt.Fprintf(&b, "  No webhook secret:           %d\n", r.Summary.NoWebhookSecret)
	fmt.Fprintf(&b, "  Insecure webhook URL:        %d\n", r.Summary.InsecureWebhookURL)
	fmt.Fprintf(&b, "  Public webhook no auth:      %d\n", r.Summary.PublicWebhookNoAuth)
	fmt.Fprintf(&b, "  Webhook no TLS:              %d\n", r.Summary.WebhookNoTLS)
	fmt.Fprintf(&b, "  Webhook replay vulnerable:   %d\n\n", r.Summary.WebhookReplayVuln)
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
