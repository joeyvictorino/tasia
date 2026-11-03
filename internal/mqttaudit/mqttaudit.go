package mqttaudit

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type Finding struct {
	Service string
	Rule    string
	Detail  string
}

type ServiceResult struct {
	Service  string
	Findings []Finding
}

type Summary struct {
	TotalServices    int
	TotalFindings    int
	AffectedServices int
	ByRule           map[string]int
}

type Report struct {
	Results []ServiceResult
	Summary Summary
}

type ruleInfo struct {
	ID string
}

var ruleAnonymousAccess = ruleInfo{ID: "MQTT-001"}
var ruleUnencrypted = ruleInfo{ID: "MQTT-002"}
var ruleDefaultCredentials = ruleInfo{ID: "MQTT-003"}
var ruleNoACL = ruleInfo{ID: "MQTT-004"}
var ruleWebSocketNoTLS = ruleInfo{ID: "MQTT-005"}
var ruleWildcardSubs = ruleInfo{ID: "MQTT-006"}

func isMQTTService(svc compose.Service) bool {
	combined := strings.ToLower(svc.Image + " " + strings.Join(svc.Command, " ") + " " + strings.Join(svc.Entrypoint, " "))
	for _, e := range svc.Environment {
		combined += " " + strings.ToLower(e)
	}
	return strings.Contains(combined, "mqtt") || strings.Contains(combined, "mosquitto") || strings.Contains(combined, "emqx") || strings.Contains(combined, "vernemq") || strings.Contains(combined, "hivemq")
}

func envVal(svc compose.Service, keys ...string) (string, bool) {
	for _, e := range svc.Environment {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.ToUpper(strings.TrimSpace(parts[0]))
		for _, key := range keys {
			if k == key {
				return strings.TrimSpace(parts[1]), true
			}
		}
	}
	return "", false
}

func envExists(svc compose.Service, keys ...string) bool {
	_, found := envVal(svc, keys...)
	return found
}

func hasPort(svc compose.Service, port string) bool {
	for _, p := range svc.Ports {
		if strings.Contains(p.Raw, port) {
			return true
		}
	}
	return false
}

func hasVolumePath(svc compose.Service, needle string) bool {
	for _, v := range svc.Volumes {
		if strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service, file string) ServiceResult {
	sr := ServiceResult{Service: svc.Name}

	if !isMQTTService(svc) {
		return sr
	}

	if v, ok := envVal(svc, "MQTT_ALLOW_ANONYMOUS", "ALLOW_ANONYMOUS"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" || low == "yes" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleAnonymousAccess.ID,
				Detail:  fmt.Sprintf("anonymous access explicitly enabled (%s)", v),
			})
		}
	}

	if hasPort(svc, "1883") && !hasPort(svc, "8883") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleUnencrypted.ID,
			Detail:  "port 1883 exposed without TLS port 8883",
		})
	}

	imgLower := strings.ToLower(svc.Image)
	if strings.Contains(imgLower, "mosquitto") || strings.Contains(imgLower, "emqx") || strings.Contains(imgLower, "vernemq") || strings.Contains(imgLower, "hivemq") {
		hasAuth := envExists(svc, "MQTT_USERNAME", "MQTT_PASSWORD", "MQTT_AUTH_FILE") ||
			hasVolumePath(svc, "password") || hasVolumePath(svc, "passwd") || hasVolumePath(svc, "auth")
		if !hasAuth {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleDefaultCredentials.ID,
				Detail:  "MQTT broker image without explicit authentication configuration",
			})
		}
	}

	if !envExists(svc, "MQTT_ACL_FILE", "ACL_FILE", "MQTT_ACL") && !hasVolumePath(svc, "acl") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleNoACL.ID,
			Detail:  "no ACL file or environment variable configured",
		})
	}

	wsEnabled := false
	if v, ok := envVal(svc, "WS_ENABLED", "MQTT_WS_ENABLED", "WEBSOCKET_ENABLED"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" {
			wsEnabled = true
		}
	}
	if hasPort(svc, "9001") {
		wsEnabled = true
	}
	if wsEnabled && !envExists(svc, "WS_TLS", "MQTT_WS_TLS", "WEBSOCKET_TLS") {
		sr.Findings = append(sr.Findings, Finding{
			Service: svc.Name,
			Rule:    ruleWebSocketNoTLS.ID,
			Detail:  "MQTT WebSocket enabled without TLS configuration",
		})
	}

	if v, ok := envVal(svc, "MQTT_ALLOW_WILDCARD", "ALLOW_WILDCARD"); ok {
		low := strings.ToLower(v)
		if low == "true" || low == "1" {
			sr.Findings = append(sr.Findings, Finding{
				Service: svc.Name,
				Rule:    ruleWildcardSubs.ID,
				Detail:  "wildcard subscriptions explicitly allowed",
			})
		}
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	var results []ServiceResult
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			sr := analyzeService(svc, cf.Path)
			results = append(results, sr)
		}
	}
	return Report{Results: results, Summary: summarize(results)}
}

func summarize(results []ServiceResult) Summary {
	s := Summary{ByRule: map[string]int{}}
	s.TotalServices = len(results)
	for _, r := range results {
		if len(r.Findings) > 0 {
			s.AffectedServices++
		}
		for _, f := range r.Findings {
			s.TotalFindings++
			s.ByRule[f.Rule]++
		}
	}
	return s
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("MQTT Broker Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "  Services scanned:   %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&b, "  Services affected:  %d\n", r.Summary.AffectedServices)
	fmt.Fprintf(&b, "  Total findings:     %d\n\n", r.Summary.TotalFindings)

	for _, sr := range r.Results {
		if len(sr.Findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  Service: %s\n", sr.Service)
		for _, f := range sr.Findings {
			fmt.Fprintf(&b, "    [%s] %s\n", f.Rule, f.Detail)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func FormatJSON(r Report) string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data) + "\n"
}
