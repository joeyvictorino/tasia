package egressmap

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

type EgressRoute struct {
	Service     string `json:"service"`
	Destination string `json:"destination"`
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol"`
	Source      string `json:"source"`
	Risk        string `json:"risk"`
}

type Summary struct {
	TotalServices int    `json:"total_services"`
	TotalRoutes   int    `json:"total_routes"`
	HighRisk      int    `json:"high_risk"`
	MediumRisk    int    `json:"medium_risk"`
	LowRisk       int    `json:"low_risk"`
	Score         int    `json:"score"`
	Grade         string `json:"grade"`
}

type Report struct {
	Routes  []EgressRoute `json:"routes"`
	Summary Summary       `json:"summary"`
}

var externalEndpointKeys = []string{
	"api_url", "api_endpoint", "api_host", "api_base",
	"webhook_url", "callback_url", "redirect_uri",
	"database_url", "redis_url", "mongo_url", "postgres_url", "mysql_url",
	"elasticsearch_url", "kafka_brokers", "rabbitmq_url", "amqp_url",
	"s3_endpoint", "aws_endpoint", "gcs_endpoint",
	"smtp_host", "mail_host",
	"proxy_url", "http_proxy", "https_proxy",
	"sentry_dsn", "datadog_url", "newrelic_host",
	"openai_api_base", "anthropic_api_base", "ollama_host",
}

func Analyze(collected *collect.Collected) Report {
	var routes []EgressRoute

	for _, cf := range collected.ComposeFiles {
		for _, svc := range cf.Services {
			routes = append(routes, extractPortRoutes(svc)...)
			routes = append(routes, extractEnvRoutes(svc)...)
			routes = append(routes, extractNetworkRoutes(svc)...)
		}
	}

	sort.Slice(routes, func(i, j int) bool {
		ri, rj := riskOrd(routes[i].Risk), riskOrd(routes[j].Risk)
		if ri != rj {
			return ri < rj
		}
		return routes[i].Service < routes[j].Service
	})

	high, med, low := 0, 0, 0
	for _, r := range routes {
		switch r.Risk {
		case "high":
			high++
		case "medium":
			med++
		case "low":
			low++
		}
	}

	services := make(map[string]bool)
	for _, r := range routes {
		services[r.Service] = true
	}

	score := 100 - high*15 - med*5 - low*2
	if score < 0 {
		score = 0
	}

	return Report{
		Routes: routes,
		Summary: Summary{
			TotalServices: len(services),
			TotalRoutes:   len(routes),
			HighRisk:      high,
			MediumRisk:    med,
			LowRisk:       low,
			Score:         score,
			Grade:         scoreGrade(score),
		},
	}
}

func extractPortRoutes(svc compose.Service) []EgressRoute {
	var routes []EgressRoute
	for _, pm := range svc.Ports {
		risk := "low"
		if pm.IsAllInterfaces() {
			risk = "medium"
		}
		if isHighRiskPort(pm.TargetPort) {
			risk = "high"
		}
		routes = append(routes, EgressRoute{
			Service:     svc.Name,
			Destination: fmt.Sprintf("0.0.0.0:%d", pm.HostPort),
			Port:        pm.TargetPort,
			Protocol:    "tcp",
			Source:      "ports",
			Risk:        risk,
		})
	}
	return routes
}

func extractEnvRoutes(svc compose.Service) []EgressRoute {
	var routes []EgressRoute
	for _, entry := range svc.Environment {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		val := parts[1]
		if !isEndpointKey(key) {
			continue
		}
		dest := extractHost(val)
		if dest == "" {
			continue
		}
		risk := "low"
		if isExternalHost(dest) {
			risk = "medium"
		}
		if strings.Contains(key, "proxy") || strings.Contains(key, "webhook") {
			risk = "high"
		}
		routes = append(routes, EgressRoute{
			Service:     svc.Name,
			Destination: dest,
			Protocol:    guessProtocol(val),
			Source:      "environment:" + parts[0],
			Risk:        risk,
		})
	}
	return routes
}

func extractNetworkRoutes(svc compose.Service) []EgressRoute {
	var routes []EgressRoute
	if svc.NetworkMode == "host" {
		routes = append(routes, EgressRoute{
			Service:     svc.Name,
			Destination: "*",
			Protocol:    "any",
			Source:      "network_mode:host",
			Risk:        "high",
		})
	}
	return routes
}

func isEndpointKey(key string) bool {
	for _, k := range externalEndpointKeys {
		if strings.Contains(key, k) {
			return true
		}
	}
	return false
}

func extractHost(val string) string {
	val = strings.TrimSpace(val)
	if strings.Contains(val, "://") {
		after := strings.SplitN(val, "://", 2)[1]
		host := strings.SplitN(after, "/", 2)[0]
		host = strings.SplitN(host, "@", 2)[len(strings.SplitN(host, "@", 2))-1]
		host = strings.SplitN(host, ":", 2)[0]
		return host
	}
	host := strings.SplitN(val, ":", 2)[0]
	if net.ParseIP(host) != nil || strings.Contains(host, ".") {
		return host
	}
	return ""
}

func isExternalHost(host string) bool {
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return !ip.IsLoopback() && !ip.IsPrivate()
	}
	if !strings.Contains(host, ".") {
		return false
	}
	return true
}

func guessProtocol(val string) string {
	lower := strings.ToLower(val)
	if strings.HasPrefix(lower, "https://") {
		return "https"
	}
	if strings.HasPrefix(lower, "http://") {
		return "http"
	}
	if strings.HasPrefix(lower, "amqp://") || strings.HasPrefix(lower, "amqps://") {
		return "amqp"
	}
	if strings.HasPrefix(lower, "redis://") || strings.HasPrefix(lower, "rediss://") {
		return "redis"
	}
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		return "postgres"
	}
	if strings.HasPrefix(lower, "mysql://") {
		return "mysql"
	}
	if strings.HasPrefix(lower, "mongodb://") || strings.HasPrefix(lower, "mongodb+srv://") {
		return "mongodb"
	}
	return "tcp"
}

func isHighRiskPort(port int) bool {
	switch port {
	case 22, 23, 3389, 5900, 6379, 27017, 9200, 5432, 3306:
		return true
	}
	return false
}

func riskOrd(r string) int {
	switch r {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}

func scoreGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func FormatText(r Report) string {
	var sb strings.Builder
	sb.WriteString("Egress Route Map\n")
	sb.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&sb, "  Services with routes: %d\n", r.Summary.TotalServices)
	fmt.Fprintf(&sb, "  Total routes:         %d\n", r.Summary.TotalRoutes)
	fmt.Fprintf(&sb, "  High risk:            %d\n", r.Summary.HighRisk)
	fmt.Fprintf(&sb, "  Medium risk:          %d\n", r.Summary.MediumRisk)
	fmt.Fprintf(&sb, "  Low risk:             %d\n", r.Summary.LowRisk)
	fmt.Fprintf(&sb, "  Score:                %d/100 (%s)\n\n", r.Summary.Score, r.Summary.Grade)

	if len(r.Routes) > 0 {
		sb.WriteString("Routes:\n")
		for i, route := range r.Routes {
			fmt.Fprintf(&sb, "  %d. [%s] %s -> %s (%s via %s)\n",
				i+1, strings.ToUpper(route.Risk), route.Service,
				route.Destination, route.Protocol, route.Source)
		}
	}

	return sb.String()
}
