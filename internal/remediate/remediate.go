package remediate

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/rules"
)

type Remediation struct {
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	Patch       string `json:"patch"`
	Confidence  string `json:"confidence"`
}

func Suggest(f rules.Finding) Remediation {
	r := Remediation{RuleID: f.ID}

	switch f.ID {
	case "exposed_inference", "exposed_ui", "exposed_vector", "exposed_datastore", "exposed_agent_runtime":
		r.Description = fmt.Sprintf("Bind the published port to localhost instead of all interfaces")
		r.Patch = formatPortPatch(f.Evidence)
		r.Confidence = "high"

	case "privileged_container":
		r.Description = "Remove privileged: true from the service"
		r.Patch = "- privileged: true\n+ # privileged removed — use specific capabilities instead\n+ cap_add:\n+   - NET_ADMIN  # only if needed"
		r.Confidence = "high"

	case "docker_socket_mount":
		r.Description = "Remove the Docker socket bind mount"
		r.Patch = "- - /var/run/docker.sock:/var/run/docker.sock\n+ # Docker socket mount removed — use Docker-out-of-Docker or a socket proxy if needed"
		r.Confidence = "high"

	case "latest_image":
		r.Description = "Pin the image to a specific version tag"
		r.Patch = formatImagePatch(f.Evidence)
		r.Confidence = "medium"

	case "permissive_cors":
		r.Description = "Restrict CORS origins to specific trusted domains"
		r.Patch = "- OLLAMA_ORIGINS=*\n+ OLLAMA_ORIGINS=http://localhost:3000,http://localhost:8080"
		r.Confidence = "medium"

	case "broad_bind_mount":
		r.Description = "Use a named volume or mount only the specific subdirectory needed"
		r.Patch = "- .:/app\n+ ./data:/app/data:ro  # mount only what the service needs, read-only if possible"
		r.Confidence = "medium"

	case "env_token_key":
		r.Description = "Move secrets to a dedicated secrets manager or Docker secrets"
		r.Patch = "# In docker-compose.yaml, use secrets:\n+ secrets:\n+   api_key:\n+     file: ./secrets/api_key.txt\n# Then reference in the service:\n+   secrets:\n+     - api_key"
		r.Confidence = "medium"

	case "env_hardcoded_secret":
		r.Description = "Remove the hardcoded secret and use environment variable substitution or Docker secrets"
		r.Patch = "- API_KEY=sk-live-abc123...\n+ API_KEY=${API_KEY}  # set in .env (gitignored) or CI secrets"
		r.Confidence = "high"

	case "no_internal_network":
		r.Description = "Add an internal network for service-to-service communication"
		r.Patch = "# Add to top-level networks:\n+ networks:\n+   internal:\n+     internal: true\n# Then attach backend services to it"
		r.Confidence = "medium"

	case "vector_db_no_auth":
		r.Description = "Enable authentication on the vector database"
		r.Patch = formatVectorAuthPatch(f.Evidence)
		r.Confidence = "medium"

	case "agent_auto_approve":
		r.Description = "Disable automatic code execution approval"
		r.Patch = "- N8N_ALLOW_EXEC=true\n+ N8N_ALLOW_EXEC=false"
		r.Confidence = "high"

	case "agent_shared_secret":
		r.Description = "Use unique secrets for each agent runtime service"
		r.Patch = "# Generate a unique secret per service:\n# openssl rand -hex 32"
		r.Confidence = "medium"

	case "agent_test_mount":
		r.Description = "Remove test directory mounts from agent runtimes"
		r.Patch = "- ./tests:/app/tests\n+ # test directory mount removed — agent runtimes should not access test fixtures"
		r.Confidence = "high"

	case "agent_auto_restart":
		r.Description = "Use on-failure restart policy with a max retry count"
		r.Patch = "- restart: always\n+ restart: on-failure:3"
		r.Confidence = "high"

	case "dockerfile_user_root":
		r.Description = "Add a non-root USER directive"
		r.Patch = "# Add before the final CMD/ENTRYPOINT:\n+ RUN addgroup --system app && adduser --system --ingroup app app\n+ USER app"
		r.Confidence = "high"

	case "dockerfile_expose_sensitive":
		r.Description = "Remove or restrict the sensitive EXPOSE port"
		r.Patch = "- EXPOSE 22\n+ # Removed sensitive port exposure"
		r.Confidence = "medium"

	case "kube_privileged":
		r.Description = "Remove privileged security context"
		r.Patch = "-   privileged: true\n+   privileged: false\n+   allowPrivilegeEscalation: false"
		r.Confidence = "high"

	case "kube_run_as_root":
		r.Description = "Run the container as a non-root user"
		r.Patch = "-   runAsUser: 0\n+   runAsUser: 1000\n+   runAsNonRoot: true"
		r.Confidence = "high"

	case "kube_host_network":
		r.Description = "Remove hostNetwork and use a Service for connectivity"
		r.Patch = "- hostNetwork: true\n+ hostNetwork: false"
		r.Confidence = "high"

	case "kube_host_path":
		r.Description = "Replace hostPath with a PersistentVolumeClaim"
		r.Patch = "- hostPath:\n-   path: /data\n+ persistentVolumeClaim:\n+   claimName: app-data"
		r.Confidence = "medium"

	case "kube_no_network_policy":
		r.Description = "Add a NetworkPolicy to restrict pod traffic"
		r.Patch = "# Create a NetworkPolicy:\n+ apiVersion: networking.k8s.io/v1\n+ kind: NetworkPolicy\n+ metadata:\n+   name: restrict-traffic\n+ spec:\n+   podSelector: {}\n+   policyTypes: [Ingress, Egress]"
		r.Confidence = "medium"

	case "kube_exposed_service":
		r.Description = "Use ClusterIP instead of LoadBalancer/NodePort"
		r.Patch = "- type: LoadBalancer\n+ type: ClusterIP"
		r.Confidence = "medium"

	case "helm_insecure_default":
		r.Description = "Override insecure defaults in your values override file"
		r.Patch = "# In your values override:\n+ securityContext:\n+   runAsNonRoot: true\n+   privileged: false"
		r.Confidence = "medium"

	case "reverse_proxy_no_auth":
		r.Description = "Add authentication to the reverse proxy"
		r.Patch = formatProxyAuthPatch(f.Evidence)
		r.Confidence = "medium"

	default:
		r.Description = fmt.Sprintf("Review and fix: %s", f.Title)
		r.Patch = fmt.Sprintf("# %s\n# See: %s", f.Why, f.Fix)
		r.Confidence = "low"
	}

	return r
}

func SuggestAll(findings []rules.Finding) []Remediation {
	out := make([]Remediation, len(findings))
	for i, f := range findings {
		out[i] = Suggest(f)
	}
	return out
}

func FormatText(remediations []Remediation) string {
	if len(remediations) == 0 {
		return "No findings to remediate.\n"
	}
	var b strings.Builder
	for i, r := range remediations {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(fmt.Sprintf("[%s] %s (confidence: %s)\n", r.RuleID, r.Description, r.Confidence))
		if r.Patch != "" {
			b.WriteString("  Suggested change:\n")
			for _, line := range strings.Split(r.Patch, "\n") {
				b.WriteString(fmt.Sprintf("    %s\n", line))
			}
		}
	}
	return b.String()
}

func formatPortPatch(evidence string) string {
	return "# Change the port binding to localhost:\n- \"0.0.0.0:PORT:PORT\"\n+ \"127.0.0.1:PORT:PORT\"\n# Or use the long form:\n+ ports:\n+   - target: PORT\n+     published: PORT\n+     host_ip: 127.0.0.1"
}

func formatImagePatch(evidence string) string {
	if strings.Contains(evidence, ":latest") {
		return "- image: example:latest\n+ image: example:1.0.0  # pin to a specific version"
	}
	return "- image: example\n+ image: example:1.0.0  # add a version tag"
}

func formatVectorAuthPatch(evidence string) string {
	lower := strings.ToLower(evidence)
	if strings.Contains(lower, "chroma") {
		return "# Add Chroma authentication:\n+ CHROMA_SERVER_AUTH_PROVIDER=chromadb.auth.token.TokenAuthServerProvider\n+ CHROMA_SERVER_AUTH_TOKEN_TRANSPORT_HEADER=Authorization"
	}
	if strings.Contains(lower, "weaviate") {
		return "# Add WEAVIATE authentication:\n+ AUTHENTICATION_APIKEY_ENABLED=true\n+ AUTHENTICATION_APIKEY_ALLOWED_KEYS=your-secret-key"
	}
	return "# Enable authentication on the vector database"
}

func formatProxyAuthPatch(evidence string) string {
	lower := strings.ToLower(evidence)
	if strings.Contains(lower, "caddy") || strings.Contains(lower, "caddyfile") {
		return "# Add basic_auth to the Caddyfile:\n+ basic_auth {\n+   user $HASHED_PASSWORD\n+ }"
	}
	return "# Add auth_request to nginx:\n+ auth_request /auth;\n+ auth_request_set $auth_status $upstream_status;"
}
