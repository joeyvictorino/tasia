package dynamodbaudit

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
	Findings []Finding `json:"findings"`
}

type Summary struct {
	NoAuth          int `json:"no_auth"`
	ExposedPort     int `json:"exposed_port"`
	DefaultRegion   int `json:"default_region"`
	SharedDB        int `json:"shared_db"`
	InMemoryStorage int `json:"in_memory_storage"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var dynamoDBImages = []string{
	"amazon/dynamodb-local", "dynamodb-local", "instructure/dynamo-local-admin",
	"deangiberson/aws-dynamodb-local", "aaronshaf/dynamodb-admin",
}

func isDynamoDBImage(image string) bool {
	img := strings.ToLower(image)
	for _, di := range dynamoDBImages {
		if strings.Contains(img, di) {
			return true
		}
	}
	return false
}

func hasAuth(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "AWS_ACCESS_KEY_ID") ||
			strings.Contains(upper, "AWS_SECRET_ACCESS_KEY") {
			return true
		}
	}
	return false
}

func hasDefaultRegion(envs []string) bool {
	for _, e := range envs {
		upper := strings.ToUpper(e)
		if strings.Contains(upper, "AWS_DEFAULT_REGION") ||
			strings.Contains(upper, "AWS_REGION") {
			return true
		}
	}
	return false
}

func hasSharedDB(cmd []string) bool {
	for _, c := range cmd {
		if strings.Contains(c, "-sharedDb") || strings.Contains(c, "--sharedDb") {
			return true
		}
	}
	return false
}

func hasInMemory(cmd []string) bool {
	for _, c := range cmd {
		if strings.Contains(c, "-inMemory") || strings.Contains(c, "--inMemory") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if !hasAuth(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "dynamodb_no_auth",
			Message: fmt.Sprintf("service %q: DynamoDB Local running without AWS credentials configured", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		8000: "DynamoDB Local HTTP API",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "dynamodb_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if !hasDefaultRegion(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "dynamodb_default_region",
			Message: fmt.Sprintf("service %q: DynamoDB Local running without explicit AWS region", svc.Name),
		})
	}

	if hasSharedDB(svc.Command) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "dynamodb_shared_db",
			Message: fmt.Sprintf("service %q: DynamoDB Local using -sharedDb flag; all clients share one database", svc.Name),
		})
	}

	if hasInMemory(svc.Command) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "low",
			Rule:    "dynamodb_in_memory",
			Message: fmt.Sprintf("service %q: DynamoDB Local using -inMemory flag; data lost on restart", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isDynamoDBImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "dynamodb_no_auth":
					r.Summary.NoAuth++
				case "dynamodb_exposed_port":
					r.Summary.ExposedPort++
				case "dynamodb_default_region":
					r.Summary.DefaultRegion++
				case "dynamodb_shared_db":
					r.Summary.SharedDB++
				case "dynamodb_in_memory":
					r.Summary.InMemoryStorage++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("DynamoDB Local Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No DynamoDB Local services found.\n")
		return b.String()
	}

	for _, svc := range r.Services {
		fmt.Fprintf(&b, "  Service: %s\n", svc.Service)
		if len(svc.Findings) == 0 {
			b.WriteString("    No findings.\n")
		}
		for _, f := range svc.Findings {
			fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Level, f.Rule, f.Message)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "  Summary: no_auth=%d exposed_port=%d default_region=%d shared_db=%d in_memory=%d\n",
		r.Summary.NoAuth, r.Summary.ExposedPort, r.Summary.DefaultRegion, r.Summary.SharedDB, r.Summary.InMemoryStorage)

	return b.String()
}
