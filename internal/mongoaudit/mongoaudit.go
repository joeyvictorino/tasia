package mongoaudit

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
	NoAuth            int `json:"no_auth"`
	DefaultCredentials int `json:"default_credentials"`
	ExposedPort       int `json:"exposed_port"`
	NoTLS             int `json:"no_tls"`
	BindAllInterfaces int `json:"bind_all_interfaces"`
	ScriptingEnabled  int `json:"scripting_enabled"`
	DebugEnabled      int `json:"debug_enabled"`
}

type Report struct {
	Path     string          `json:"path"`
	Services []ServiceResult `json:"services"`
	Summary  Summary         `json:"summary"`
}

var mongoImages = []string{
	"mongo", "bitnami/mongodb", "percona/percona-server-mongodb",
	"arm64v8/mongo", "amd64/mongo", "circleci/mongo",
}

func isMongoImage(image string) bool {
	img := strings.ToLower(image)
	for _, mi := range mongoImages {
		if strings.Contains(img, mi) {
			return true
		}
	}
	return false
}

func hasNoAuth(envs []string, command []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "mongo_initdb_root_username=") {
			return false
		}
		if strings.Contains(lower, "auth=false") ||
			strings.Contains(lower, "noauth") {
			return true
		}
	}
	for _, c := range command {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "--noauth") {
			return true
		}
	}
	return false
}

func hasDefaultCredentials(envs []string) bool {
	defaults := []string{"admin", "root", "mongo", "password", "changeme", "default"}
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "mongo_initdb_root_password=") ||
			strings.Contains(lower, "mongodb_root_password=") {
			for _, d := range defaults {
				if strings.Contains(lower, "="+d) {
					return true
				}
			}
		}
	}
	return false
}

func hasNoTLS(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "tls=false") ||
			strings.Contains(lower, "ssl=false") ||
			strings.Contains(lower, "tlsmode=disabled") ||
			strings.Contains(lower, "sslmode=disabled") {
			return true
		}
	}
	return false
}

func hasBindAllInterfaces(envs []string, command []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "bind_ip=0.0.0.0") ||
			strings.Contains(lower, "bind_ip_all=true") {
			return true
		}
	}
	for _, c := range command {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "--bind_ip_all") ||
			strings.Contains(lower, "--bind_ip=0.0.0.0") {
			return true
		}
	}
	return false
}

func hasScriptingEnabled(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "scripting=true") ||
			strings.Contains(lower, "javascriptenabled=true") {
			return true
		}
	}
	return false
}

func hasDebugEnabled(envs []string) bool {
	for _, e := range envs {
		lower := strings.ToLower(e)
		if strings.Contains(lower, "verbose") && strings.Contains(lower, "=true") {
			return true
		}
		if strings.Contains(lower, "logLevel=0") {
			return true
		}
	}
	return false
}

func analyzeService(svc compose.Service) ServiceResult {
	sr := ServiceResult{Service: svc.Name}
	envs := svc.Environment

	if hasNoAuth(envs, svc.Command) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "mongo_no_auth",
			Message: fmt.Sprintf("service %q: MongoDB authentication disabled", svc.Name),
		})
	}

	if hasDefaultCredentials(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "critical",
			Rule:    "mongo_default_credentials",
			Message: fmt.Sprintf("service %q: MongoDB using default/weak credentials", svc.Name),
		})
	}

	exposedPorts := map[int]string{
		27017: "MongoDB",
		27018: "MongoDB shard",
		27019: "MongoDB config server",
		28017: "MongoDB HTTP interface",
	}
	for _, p := range svc.Ports {
		if desc, ok := exposedPorts[p.TargetPort]; ok {
			if p.IsAllInterfaces() {
				sr.Findings = append(sr.Findings, Finding{
					Level:   "high",
					Rule:    "mongo_exposed_port",
					Message: fmt.Sprintf("service %q: port %d (%s) exposed on all interfaces", svc.Name, p.TargetPort, desc),
				})
			}
		}
	}

	if hasNoTLS(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "mongo_no_tls",
			Message: fmt.Sprintf("service %q: MongoDB TLS/SSL disabled", svc.Name),
		})
	}

	if hasBindAllInterfaces(envs, svc.Command) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "high",
			Rule:    "mongo_bind_all",
			Message: fmt.Sprintf("service %q: MongoDB bound to all interfaces", svc.Name),
		})
	}

	if hasScriptingEnabled(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "mongo_scripting_enabled",
			Message: fmt.Sprintf("service %q: MongoDB server-side scripting enabled", svc.Name),
		})
	}

	if hasDebugEnabled(envs) {
		sr.Findings = append(sr.Findings, Finding{
			Level:   "medium",
			Rule:    "mongo_debug_enabled",
			Message: fmt.Sprintf("service %q: MongoDB verbose/debug logging enabled", svc.Name),
		})
	}

	return sr
}

func Analyze(c *collect.Collected) Report {
	r := Report{Path: c.Root}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			if !isMongoImage(svc.Image) {
				continue
			}
			sr := analyzeService(svc)
			r.Services = append(r.Services, sr)
			for _, f := range sr.Findings {
				switch f.Rule {
				case "mongo_no_auth":
					r.Summary.NoAuth++
				case "mongo_default_credentials":
					r.Summary.DefaultCredentials++
				case "mongo_exposed_port":
					r.Summary.ExposedPort++
				case "mongo_no_tls":
					r.Summary.NoTLS++
				case "mongo_bind_all":
					r.Summary.BindAllInterfaces++
				case "mongo_scripting_enabled":
					r.Summary.ScriptingEnabled++
				case "mongo_debug_enabled":
					r.Summary.DebugEnabled++
				}
			}
		}
	}
	return r
}

func FormatText(r Report) string {
	var b strings.Builder
	b.WriteString("MongoDB Security Audit\n")
	b.WriteString(strings.Repeat("=", 50) + "\n")
	fmt.Fprintf(&b, "Path: %s\n\n", r.Path)

	if len(r.Services) == 0 {
		b.WriteString("  No MongoDB services found.\n")
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

	fmt.Fprintf(&b, "  Summary: no_auth=%d default_creds=%d exposed=%d no_tls=%d bind_all=%d scripting=%d debug=%d\n",
		r.Summary.NoAuth, r.Summary.DefaultCredentials, r.Summary.ExposedPort,
		r.Summary.NoTLS, r.Summary.BindAllInterfaces, r.Summary.ScriptingEnabled, r.Summary.DebugEnabled)

	return b.String()
}
