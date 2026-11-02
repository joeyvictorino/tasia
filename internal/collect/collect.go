// Package collect walks a directory tree and parses Docker Compose,
// .env, Dockerfile, Caddyfile, nginx.conf, Kubernetes manifest and Helm
// values.yaml files into structured data. The result is a [Collected]
// value that the rules package inspects. Parsing uses yaml.v3 nodes for
// accurate line numbers and never reads secret values into the output.
package collect

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

// Collected holds the aggregated data from scanning a tree.
// Pure data for rules and reports.
type Collected struct {
	Root               string
	ComposeFiles       []compose.File
	EnvFiles           []EnvFile
	Dockerfiles        []Dockerfile
	ReverseProxyConfigs []ReverseProxyConfig
	KubeManifests       []KubeManifest
	HelmValues          []HelmValues
	OtherConfigs        []string // Modelfile etc later
	DetectedRuntimes   []string
	DetectedInterfaces []string
	DetectedRetrieval  []string
	// DetectedAgentRuntimes lists agent runtimes and workflow engines that
	// execute tools or model-written code (n8n, Flowise, Langflow, Dify,
	// OpenHands and similar). See IsAgentRuntimeImage.
	DetectedAgentRuntimes []string
	PublishedPorts        []int
	SecretKeyNames        []string
	HasManifest           bool
	HasNetworkPolicy      bool
	ParseErrors           []ConfigError
}

// ConfigError records a config file that was found but could not be parsed.
// The gate must fail closed when any are present: an unparseable config cannot
// be vouched for, so reporting PASS on it would defeat the tool's purpose.
type ConfigError struct {
	Path string
	Err  string
}

// EnvFile tracks .env* without values.
type EnvFile struct {
	Path string
	Keys []EnvKey
}

// EnvKey is a secret-looking key name and the 1-based line it appears on.
// Values are never captured. ValuePattern is set only when the value
// matches a known secret pattern (e.g. "sk- prefix"); the actual value
// is never stored.
type EnvKey struct {
	Name         string
	Line         int
	ValuePattern string // empty unless value matches a known pattern
}

// KeyNames returns just the key names (values are never stored).
func (e EnvFile) KeyNames() []string {
	out := make([]string, 0, len(e.Keys))
	for _, k := range e.Keys {
		out = append(out, k.Name)
	}
	return out
}

// ReverseProxyConfig holds a parsed Caddyfile or nginx.conf with
// security-relevant proxy and auth information.
type ReverseProxyConfig struct {
	Path    string
	Kind    string // "caddyfile" or "nginx"
	Content string
	Proxies []ProxyBlock
}

// ProxyBlock records one reverse_proxy (Caddy) or location+proxy_pass (nginx)
// directive with whether auth is configured for it.
type ProxyBlock struct {
	Upstream string
	Line     int
	HasAuth  bool
}

// ParseCaddyfile extracts reverse_proxy directives and whether they are
// protected by basic_auth or forward_auth.
func ParseCaddyfile(path, content string) ReverseProxyConfig {
	cfg := ReverseProxyConfig{Path: path, Kind: "caddyfile", Content: content}
	lines := strings.Split(content, "\n")
	depth := 0
	var currentProxy *ProxyBlock
	blockHasAuth := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "{") {
			depth++
		}
		if strings.Contains(trimmed, "}") {
			if depth > 0 {
				depth--
			}
			if currentProxy != nil && depth <= 1 {
				currentProxy.HasAuth = blockHasAuth
				cfg.Proxies = append(cfg.Proxies, *currentProxy)
				currentProxy = nil
				blockHasAuth = false
			}
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "basic_auth") || strings.HasPrefix(lower, "forward_auth") {
			blockHasAuth = true
		}
		if strings.HasPrefix(lower, "reverse_proxy") {
			parts := strings.Fields(trimmed)
			upstream := ""
			for j := len(parts) - 1; j >= 1; j-- {
				if parts[j] == "{" {
					continue
				}
				upstream = parts[j]
				break
			}
			if strings.Contains(trimmed, "{") {
				currentProxy = &ProxyBlock{Upstream: upstream, Line: i + 1}
			} else {
				cfg.Proxies = append(cfg.Proxies, ProxyBlock{
					Upstream: upstream,
					Line:     i + 1,
					HasAuth:  blockHasAuth,
				})
			}
		}
	}
	if currentProxy != nil {
		currentProxy.HasAuth = blockHasAuth
		cfg.Proxies = append(cfg.Proxies, *currentProxy)
	}
	return cfg
}

// ParseNginxConf extracts proxy_pass directives and whether their enclosing
// location block has auth_basic or auth_request.
func ParseNginxConf(path, content string) ReverseProxyConfig {
	cfg := ReverseProxyConfig{Path: path, Kind: "nginx", Content: content}
	lines := strings.Split(content, "\n")
	type locCtx struct {
		hasAuth bool
	}
	var locStack []locCtx
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "location") && strings.Contains(trimmed, "{") {
			locStack = append(locStack, locCtx{})
		}
		if strings.HasPrefix(lower, "auth_basic") && !strings.Contains(lower, "auth_basic_user_file") && !strings.HasSuffix(lower, "off;") {
			if len(locStack) > 0 {
				locStack[len(locStack)-1].hasAuth = true
			}
		}
		if strings.HasPrefix(lower, "auth_request") && !strings.HasSuffix(lower, "off;") {
			if len(locStack) > 0 {
				locStack[len(locStack)-1].hasAuth = true
			}
		}
		if strings.Contains(lower, "proxy_pass") {
			parts := strings.Fields(trimmed)
			upstream := ""
			for j, p := range parts {
				if strings.ToLower(p) == "proxy_pass" && j+1 < len(parts) {
					upstream = strings.TrimSuffix(parts[j+1], ";")
					break
				}
			}
			hasAuth := false
			if len(locStack) > 0 {
				hasAuth = locStack[len(locStack)-1].hasAuth
			}
			cfg.Proxies = append(cfg.Proxies, ProxyBlock{
				Upstream: upstream,
				Line:     i + 1,
				HasAuth:  hasAuth,
			})
		}
		if strings.Contains(trimmed, "}") && len(locStack) > 0 {
			locStack = locStack[:len(locStack)-1]
		}
	}
	return cfg
}

// Dockerfile holds a parsed Dockerfile with line-level information about
// security-relevant directives.
type Dockerfile struct {
	Path    string
	Content string
	// User is the effective USER from the last USER directive, or "" if none.
	User     string
	UserLine int
	// Exposes lists EXPOSE directives with their port strings and lines.
	Exposes []DockerfileExpose
}

// DockerfileExpose records one EXPOSE directive.
type DockerfileExpose struct {
	Ports string // the raw port list, e.g. "8080 443/tcp"
	Line  int
}

// ParseDockerfile extracts security-relevant directives from Dockerfile content.
func ParseDockerfile(path, content string) Dockerfile {
	df := Dockerfile{Path: path, Content: content}
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "USER ") {
			df.User = strings.TrimSpace(trimmed[5:])
			df.UserLine = i + 1
		}
		if strings.HasPrefix(upper, "EXPOSE ") {
			df.Exposes = append(df.Exposes, DockerfileExpose{
				Ports: strings.TrimSpace(trimmed[7:]),
				Line:  i + 1,
			})
		}
	}
	return df
}

// isComposeFile matches Docker Compose file names including overrides and
// variant files (docker-compose.override.yml, docker-compose.prod.yaml, etc.).
func isComposeFile(lower string) bool {
	switch lower {
	case "docker-compose.yml", "docker-compose.yaml",
		"compose.yml", "compose.yaml":
		return true
	}
	if strings.HasPrefix(lower, "docker-compose.") || strings.HasPrefix(lower, "compose.") {
		return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
	}
	return false
}

// WalkAndCollect walks the dir and extracts relevant data.
func WalkAndCollect(root string) (*Collected, error) {
	c := &Collected{Root: root}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// skip .git, .tasia, node_modules etc
			name := d.Name()
			if name == ".git" || name == ".tasia" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		lower := strings.ToLower(d.Name())

		switch {
		case isComposeFile(lower):
			f, perr := compose.Parse(path)
			if perr != nil {
				// Fail closed: an unparseable compose file is recorded so the
				// gate reports ERROR rather than silently vouching for it.
				c.ParseErrors = append(c.ParseErrors, ConfigError{Path: rel, Err: perr.Error()})
				return nil
			}
			c.ComposeFiles = append(c.ComposeFiles, *f)
			extractFromCompose(c, f)
		case strings.HasPrefix(lower, ".env"):
			ef, perr := parseEnvKeys(path)
			if perr != nil {
				c.ParseErrors = append(c.ParseErrors, ConfigError{Path: rel, Err: perr.Error()})
				return nil
			}
			if r, err := filepath.Rel(root, path); err == nil {
				ef.Path = r
			}
			c.EnvFiles = append(c.EnvFiles, ef)
			c.SecretKeyNames = append(c.SecretKeyNames, ef.KeyNames()...)
		case lower == "dockerfile":
			content, _ := os.ReadFile(path)
			c.Dockerfiles = append(c.Dockerfiles, ParseDockerfile(rel, string(content)))
		case lower == "caddyfile":
			content, _ := os.ReadFile(path)
			c.ReverseProxyConfigs = append(c.ReverseProxyConfigs, ParseCaddyfile(rel, string(content)))
		case lower == "nginx.conf":
			content, _ := os.ReadFile(path)
			c.ReverseProxyConfigs = append(c.ReverseProxyConfigs, ParseNginxConf(rel, string(content)))
		case lower == "modelfile":
			c.OtherConfigs = append(c.OtherConfigs, rel)
		case lower == "ai-stack-manifest.json":
			c.HasManifest = true
		default:
			if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
				content, rerr := os.ReadFile(path)
				if rerr != nil {
					break
				}
				s := string(content)
				if IsHelmValuesFile(lower) && hasChartYAML(filepath.Dir(path)) {
					hv := ParseHelmValues(rel, s)
					if len(hv.Findings) > 0 {
						c.HelmValues = append(c.HelmValues, hv)
					}
				} else if IsKubeFile(lower, s) {
					manifests, _ := ParseKubeYAML(rel, s)
					c.KubeManifests = append(c.KubeManifests, manifests...)
					for _, m := range manifests {
						if m.Kind == "NetworkPolicy" {
							c.HasNetworkPolicy = true
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// dedup secrets etc
	c.SecretKeyNames = dedup(c.SecretKeyNames)
	c.PublishedPorts = dedupInts(c.PublishedPorts)

	// runtime / interface / retrieval detection from collected service images
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			name := strings.ToLower(svc.Image)
			for label, needles := range map[string][]string{
				"ollama":    {"ollama"},
				"vllm":      {"vllm"},
				"llama.cpp": {"llama.cpp", "llamacpp"},
				"lm-studio": {"lmstudio", "lm-studio"},
			} {
				if containsAny(name, needles) {
					c.DetectedRuntimes = append(c.DetectedRuntimes, label)
				}
			}
			for label, needles := range map[string][]string{
				"open-webui": {"open-webui", "openwebui"},
				"gradio":     {"gradio"},
			} {
				if containsAny(name, needles) {
					c.DetectedInterfaces = append(c.DetectedInterfaces, label)
				}
			}
			if label, ok := IsAgentRuntimeImage(svc.Image); ok {
				c.DetectedAgentRuntimes = append(c.DetectedAgentRuntimes, label)
			}
			for label, needles := range map[string][]string{
				"qdrant":   {"qdrant"},
				"chroma":   {"chroma"},
				"weaviate": {"weaviate"},
				"milvus":   {"milvus"},
				"redis":    {"redis", "valkey"},
				"postgres": {"postgres", "pgvector"},
			} {
				if containsAny(name, needles) {
					c.DetectedRetrieval = append(c.DetectedRetrieval, label)
				}
			}
		}
	}
	c.DetectedRuntimes = sortStrings(dedup(c.DetectedRuntimes))
	c.DetectedInterfaces = sortStrings(dedup(c.DetectedInterfaces))
	c.DetectedRetrieval = sortStrings(dedup(c.DetectedRetrieval))
	c.DetectedAgentRuntimes = sortStrings(dedup(c.DetectedAgentRuntimes))

	return c, nil
}

// agentRuntimeSubstrings identify agent runtimes by a substring of the image
// reference. Each entry is distinctive enough not to match unrelated images.
var agentRuntimeSubstrings = []struct{ label, needle string }{
	{"flowise", "flowise"},
	{"langflow", "langflow"},
	{"dify", "langgenius/dify"},
	{"dify", "dify-api"},
	{"openhands", "openhands"},
	{"openhands", "all-hands"},
	{"open-interpreter", "open-interpreter"},
	{"open-interpreter", "openinterpreter"},
	{"memdoor", "memdoor"},
	{"crewai", "crewai"},
}

// agentRuntimeRepoNames identify agent runtimes whose short names would match
// too much as substrings (n8n-docs, autogenerated-*), so they must equal the
// image's final path segment with the tag or digest removed.
var agentRuntimeRepoNames = map[string]string{
	"n8n":            "n8n",
	"autogen":        "autogen",
	"autogen-studio": "autogen",
	"autogenstudio":  "autogen",
	"dify":           "dify",
}

// IsAgentRuntimeImage reports whether an image reference names an agent
// runtime or workflow engine that executes tools or model-written code, and
// returns its label. It is the single source of truth shared by the collector
// (for the stack manifest) and the rules engine (for exposure rules).
func IsAgentRuntimeImage(image string) (string, bool) {
	img := strings.ToLower(strings.TrimSpace(image))
	if img == "" {
		return "", false
	}
	for _, r := range agentRuntimeSubstrings {
		if strings.Contains(img, r.needle) {
			return r.label, true
		}
	}
	repo := img
	if i := strings.LastIndex(repo, "/"); i >= 0 {
		repo = repo[i+1:]
	}
	if i := strings.IndexAny(repo, ":@"); i >= 0 {
		repo = repo[:i]
	}
	if label, ok := agentRuntimeRepoNames[repo]; ok {
		return label, true
	}
	return "", false
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func sortStrings(ss []string) []string {
	sort.Strings(ss)
	return ss
}

func extractFromCompose(c *Collected, f *compose.File) {
	for _, svc := range f.Services {
		// ports
		for _, p := range svc.Ports {
			if p.HostPort > 0 {
				c.PublishedPorts = append(c.PublishedPorts, p.HostPort)
			}
		}
		// compose environment secret key names (values ignored)
		for _, e := range svc.Environment {
			if idx := strings.Index(e, "="); idx > 0 {
				k := strings.TrimSpace(e[:idx])
				if LooksLikeSecretKeyName(k) {
					c.SecretKeyNames = append(c.SecretKeyNames, k)
				}
			} else if LooksLikeSecretKeyName(e) {
				c.SecretKeyNames = append(c.SecretKeyNames, strings.TrimSpace(e))
			}
		}
		// images for detection later too
		// mounts, privileged, etc handled in rules or here
	}
}

func parseEnvKeys(path string) (EnvFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return EnvFile{}, err
	}
	keys := []EnvKey{}
	lines := strings.Split(string(b), "\n")
	re := regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z0-9_]+)\s*=(.*)`)
	for i, ln := range lines {
		m := re.FindStringSubmatch(ln)
		if m != nil {
			k := m[1]
			v := strings.TrimSpace(m[2])
			v = strings.Trim(v, `"'`)
			if LooksLikeSecretKeyName(k) {
				keys = append(keys, EnvKey{Name: k, Line: i + 1, ValuePattern: LooksLikeSecretValue(v)})
			} else if pat := LooksLikeSecretValue(v); pat != "" {
				keys = append(keys, EnvKey{Name: k, Line: i + 1, ValuePattern: pat})
			}
		}
	}
	return EnvFile{Path: path, Keys: keys}, nil
}

// LooksLikeSecretKeyName reports whether an environment key name suggests it
// holds a credential. It inspects only the name, never the value. This is the
// single source of truth shared by the collector and the rules engine.
func LooksLikeSecretKeyName(k string) bool {
	uk := strings.ToUpper(k)
	return strings.Contains(uk, "TOKEN") || strings.Contains(uk, "KEY") || strings.Contains(uk, "SECRET") ||
		strings.Contains(uk, "PASS") || strings.Contains(uk, "API") || strings.Contains(uk, "HF_") ||
		strings.Contains(uk, "AUTH")
}

// LooksLikeSecretValue reports whether a value matches a known secret
// pattern. Returns the pattern name if matched, empty string otherwise.
// The actual value is never stored in findings.
func LooksLikeSecretValue(v string) string {
	if v == "" || v == "changeme" || v == "TODO" || v == "placeholder" {
		return ""
	}
	prefixes := []struct {
		prefix  string
		pattern string
	}{
		{"sk-", "sk- prefix (OpenAI/Stripe)"},
		{"sk_live_", "sk_live_ prefix (Stripe live)"},
		{"rk_live_", "rk_live_ prefix (Stripe restricted)"},
		{"pk_live_", "pk_live_ prefix (Stripe publishable)"},
		{"ghp_", "ghp_ prefix (GitHub PAT)"},
		{"ghs_", "ghs_ prefix (GitHub App)"},
		{"gho_", "gho_ prefix (GitHub OAuth)"},
		{"github_pat_", "github_pat_ prefix"},
		{"glpat-", "glpat- prefix (GitLab PAT)"},
		{"xoxb-", "xoxb- prefix (Slack bot)"},
		{"xoxp-", "xoxp- prefix (Slack user)"},
		{"xapp-", "xapp- prefix (Slack app)"},
		{"AKIA", "AKIA prefix (AWS access key)"},
		{"whsec_", "whsec_ prefix (webhook secret)"},
		{"hf_", "hf_ prefix (Hugging Face)"},
		{"eyJ", "eyJ prefix (JWT/base64 token)"},
		{"shpat_", "shpat_ prefix (Shopify)"},
		{"sq0atp-", "sq0atp- prefix (Square)"},
		{"SG.", "SG. prefix (SendGrid)"},
	}
	for _, p := range prefixes {
		if strings.HasPrefix(v, p.prefix) {
			return p.pattern
		}
	}
	if isHexString(v) && len(v) >= 32 {
		return "hex string >=32 chars"
	}
	if isBase64Like(v) && len(v) >= 20 {
		return "base64-like string >=20 chars"
	}
	return ""
}

func isHexString(s string) bool {
	if len(s) < 32 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isBase64Like(s string) bool {
	if len(s) < 20 {
		return false
	}
	alphaNum := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '-' || c == '_' {
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
				alphaNum++
			}
		} else {
			return false
		}
	}
	return float64(alphaNum)/float64(len(s)) > 0.7
}

func dedup(ss []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, s := range ss {
		if !m[s] {
			m[s] = true
			out = append(out, s)
		}
	}
	return out
}

func dedupInts(is []int) []int {
	m := map[int]bool{}
	out := []int{}
	for _, i := range is {
		if !m[i] {
			m[i] = true
			out = append(out, i)
		}
	}
	return out
}

func hasChartYAML(dir string) bool {
	for _, name := range []string{"Chart.yaml", "Chart.yml"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}
