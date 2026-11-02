package rules

// RuleInfo describes one deterministic rule for the catalog.
type RuleInfo struct {
	ID          string   `json:"id"`
	Default     Severity `json:"default_severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
}

// CatalogMap returns a map from rule ID to RuleInfo for fast lookup.
func CatalogMap() map[string]RuleInfo {
	m := make(map[string]RuleInfo)
	for _, r := range Catalog() {
		m[r.ID] = r
	}
	return m
}

// Catalog returns every rule tasia can fire, in a stable order grouped by
// category. This is the single source of truth for `tasia rules` and the
// v1.0 findings JSON schema.
func Catalog() []RuleInfo {
	return []RuleInfo{
		// Compose — exposure
		{ID: "exposed_inference", Default: SeverityHigh, Title: "Inference API published to all interfaces", Description: "Ollama, vLLM, llama.cpp or LM Studio port bound to 0.0.0.0", Category: "compose"},
		{ID: "exposed_ui", Default: SeverityHigh, Title: "Chat UI published to all interfaces", Description: "Open WebUI or Gradio port bound to 0.0.0.0", Category: "compose"},
		{ID: "exposed_vector", Default: SeverityHigh, Title: "Vector DB published to host", Description: "Qdrant, Chroma, Weaviate or Milvus port bound to 0.0.0.0", Category: "compose"},
		{ID: "exposed_datastore", Default: SeverityMedium, Title: "Data store published to all interfaces", Description: "Redis, Valkey, Postgres or pgvector port exposed (HIGH alongside AI components)", Category: "compose"},
		{ID: "exposed_agent_runtime", Default: SeverityHigh, Title: "Agent runtime published to all interfaces", Description: "n8n, Flowise, Langflow, Dify, OpenHands or similar agent service exposed", Category: "compose"},

		// Compose — container security
		{ID: "docker_socket_mount", Default: SeverityCritical, Title: "Docker socket mounted", Description: "/var/run/docker.sock bind-mounted into a container", Category: "compose"},
		{ID: "privileged_container", Default: SeverityCritical, Title: "Privileged container", Description: "Container runs with privileged: true", Category: "compose"},
		{ID: "permissive_cors", Default: SeverityHigh, Title: "Permissive CORS", Description: "OLLAMA_ORIGINS=* or similar wildcard CORS setting", Category: "compose"},
		{ID: "latest_image", Default: SeverityMedium, Title: "Mutable image tag", Description: "image: uses :latest or no tag", Category: "compose"},
		{ID: "broad_bind_mount", Default: SeverityMedium, Title: "Broad writable bind mount", Description: "Broad volume like .:/app mounted writable (HIGH on agent runtimes)", Category: "compose"},
		{ID: "env_token_key", Default: SeverityMedium, Title: "Secret key name in config", Description: "Token/secret/key name found in .env or compose environment (value never read)", Category: "compose"},
		{ID: "env_hardcoded_secret", Default: SeverityHigh, Title: "Hardcoded secret value", Description: "Value matches a known secret pattern (sk-, ghp_, AKIA, JWT, hex/base64 blob); value never emitted", Category: "compose"},
		{ID: "no_internal_network", Default: SeverityMedium, Title: "No internal network separation", Description: "Multi-service stack with published ports but no internal: true network", Category: "compose"},

		// Compose — vector DB auth
		{ID: "vector_db_no_auth", Default: SeverityLow, Title: "Vector DB without authentication", Description: "Chroma or Weaviate running without authentication configuration", Category: "compose"},

		// Compose — agent runtime
		{ID: "agent_auto_approve", Default: SeverityHigh, Title: "Agent auto-approve or code execution", Description: "N8N_ALLOW_EXEC, FLOWISE_ALLOW_CODE_EXEC, AUTO_APPROVE or similar enabled", Category: "agent"},
		{ID: "agent_shared_secret", Default: SeverityHigh, Title: "Shared secret across agent runtimes", Description: "Same secret key name used by multiple agent runtime services", Category: "agent"},
		{ID: "agent_test_mount", Default: SeverityHigh, Title: "Test directory mounted into agent", Description: "test/, spec/, fixtures/ or similar mounted writable into agent runtime", Category: "agent"},
		{ID: "agent_auto_restart", Default: SeverityMedium, Title: "Agent runtime auto-restart", Description: "restart: always or unless-stopped on an agent runtime (retries destructive actions)", Category: "agent"},

		// Manifest
		{ID: "no_ai_stack_manifest", Default: SeverityLow, Title: "No AI stack manifest", Description: "No ai-stack-manifest.json found in the scanned directory", Category: "manifest"},

		// Dockerfile
		{ID: "dockerfile_user_root", Default: SeverityHigh, Title: "Dockerfile runs as root", Description: "USER root or USER 0 in Dockerfile", Category: "dockerfile"},
		{ID: "dockerfile_expose", Default: SeverityLow, Title: "Dockerfile EXPOSE directive", Description: "EXPOSE directive in Dockerfile (informational)", Category: "dockerfile"},
		{ID: "dockerfile_expose_sensitive", Default: SeverityMedium, Title: "Dockerfile exposes sensitive port", Description: "EXPOSE of database, SSH or Docker daemon port", Category: "dockerfile"},

		// Reverse proxy
		{ID: "reverse_proxy_no_auth", Default: SeverityMedium, Title: "Reverse proxy without authentication", Description: "Caddyfile or nginx reverse proxy with no basic_auth, forward_auth or auth_request", Category: "proxy"},

		// Kubernetes
		{ID: "kube_exposed_service", Default: SeverityHigh, Title: "Kubernetes Service exposed externally", Description: "Service type LoadBalancer or NodePort exposes pods outside the cluster", Category: "kubernetes"},
		{ID: "kube_privileged", Default: SeverityCritical, Title: "Kubernetes privileged container", Description: "securityContext.privileged: true on a container", Category: "kubernetes"},
		{ID: "kube_run_as_root", Default: SeverityHigh, Title: "Kubernetes container runs as root", Description: "runAsUser: 0 or runAsNonRoot: false on a container", Category: "kubernetes"},
		{ID: "kube_host_network", Default: SeverityHigh, Title: "Kubernetes pod on host network", Description: "hostNetwork: true puts pod on the host's network stack", Category: "kubernetes"},
		{ID: "kube_host_path", Default: SeverityHigh, Title: "Kubernetes hostPath mount", Description: "hostPath volume gives container direct host filesystem access (CRITICAL for sensitive paths)", Category: "kubernetes"},
		{ID: "kube_no_network_policy", Default: SeverityMedium, Title: "Kubernetes workloads without NetworkPolicy", Description: "Workloads defined without a NetworkPolicy restricting pod-to-pod and egress traffic", Category: "kubernetes"},

		// Helm
		{ID: "helm_insecure_default", Default: SeverityHigh, Title: "Helm values.yaml insecure default", Description: "Insecure default in values.yaml (privileged, hostNetwork, runAsUser 0, LoadBalancer/NodePort, hostPath)", Category: "helm"},

		// Terraform
		{ID: "tf_sg_ingress_all", Default: SeverityCritical, Title: "Security group allows all inbound traffic", Description: "AWS security group ingress rule with 0.0.0.0/0 and all ports/protocols", Category: "terraform"},
		{ID: "tf_sg_ingress_sensitive", Default: SeverityHigh, Title: "Security group exposes sensitive port to internet", Description: "AWS security group ingress from 0.0.0.0/0 on SSH, database, or admin port", Category: "terraform"},
		{ID: "tf_sg_ingress_wide", Default: SeverityMedium, Title: "Security group allows internet ingress", Description: "AWS security group ingress from 0.0.0.0/0 on a non-sensitive port", Category: "terraform"},
		{ID: "tf_s3_public_acl", Default: SeverityHigh, Title: "S3 bucket with public ACL", Description: "S3 bucket uses public-read or public-read-write ACL", Category: "terraform"},
		{ID: "tf_iam_admin_access", Default: SeverityCritical, Title: "IAM policy grants unrestricted admin access", Description: "IAM policy with Effect=Allow actions=[*] resources=[*]", Category: "terraform"},
		{ID: "tf_iam_star_actions", Default: SeverityHigh, Title: "IAM policy grants all actions", Description: "IAM policy with Effect=Allow actions=[*]", Category: "terraform"},

		// Terraform — GCP
		{ID: "tf_gcp_firewall_ingress_all", Default: SeverityCritical, Title: "GCP firewall allows all inbound traffic", Description: "GCP compute firewall with source_ranges 0.0.0.0/0 and all ports", Category: "terraform"},
		{ID: "tf_gcp_firewall_ingress_sensitive", Default: SeverityHigh, Title: "GCP firewall exposes sensitive port to internet", Description: "GCP compute firewall with source_ranges 0.0.0.0/0 on SSH, database, or admin port", Category: "terraform"},
		{ID: "tf_gcp_firewall_ingress_wide", Default: SeverityMedium, Title: "GCP firewall allows internet ingress", Description: "GCP compute firewall with source_ranges 0.0.0.0/0 on a non-sensitive port", Category: "terraform"},
		{ID: "tf_gcp_storage_public", Default: SeverityHigh, Title: "GCP storage bucket with public access", Description: "GCS bucket ACL or IAM binding grants allUsers or allAuthenticatedUsers", Category: "terraform"},

		// Terraform — Azure
		{ID: "tf_azure_nsg_ingress_all", Default: SeverityCritical, Title: "Azure NSG allows all inbound traffic", Description: "Azure network security rule with source * and all ports", Category: "terraform"},
		{ID: "tf_azure_nsg_ingress_sensitive", Default: SeverityHigh, Title: "Azure NSG exposes sensitive port to internet", Description: "Azure network security rule with internet source on SSH, database, or admin port", Category: "terraform"},
		{ID: "tf_azure_nsg_ingress_wide", Default: SeverityMedium, Title: "Azure NSG allows internet ingress", Description: "Azure network security rule with internet source on a non-sensitive port", Category: "terraform"},
		{ID: "tf_azure_storage_public", Default: SeverityHigh, Title: "Azure storage account allows public blob access", Description: "Azure storage account with allow_blob_public_access = true", Category: "terraform"},

		// Terraform — Lambda / ECS
		{ID: "tf_lambda_admin_role", Default: SeverityHigh, Title: "Lambda function with admin execution role", Description: "AWS Lambda function whose execution role grants AdministratorAccess", Category: "terraform"},
		{ID: "tf_lambda_vpc_no_sg", Default: SeverityMedium, Title: "Lambda in VPC without security groups", Description: "AWS Lambda in a VPC with empty security_group_ids", Category: "terraform"},
		{ID: "tf_ecs_privileged", Default: SeverityHigh, Title: "ECS task runs privileged container", Description: "ECS task definition with privileged: true in container_definitions", Category: "terraform"},
		{ID: "tf_ecs_root", Default: SeverityMedium, Title: "ECS task runs container as root", Description: "ECS task definition with user root or 0 in container_definitions", Category: "terraform"},
	}
}
