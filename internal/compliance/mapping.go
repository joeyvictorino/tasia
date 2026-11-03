package compliance

import "sort"

type Control struct {
	Framework string `json:"framework"`
	ControlID string `json:"control_id"`
	Name      string `json:"name"`
}

type RuleMapping struct {
	RuleID   string    `json:"rule_id"`
	Controls []Control `json:"controls"`
}

const (
	SOC2    = "SOC2"
	NISTAI  = "NIST-AI-RMF"
	OWASPLLM = "OWASP-LLM-Top10"
)

var mappings = []RuleMapping{
	{RuleID: "privileged_container", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
		{OWASPLLM, "LLM09", "Improper Output Handling"},
	}},
	{RuleID: "docker_socket_mount", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{SOC2, "CC6.3", "Role-Based Access Controls"},
		{NISTAI, "GOVERN-1.2", "Trustworthy AI characteristics"},
		{OWASPLLM, "LLM09", "Improper Output Handling"},
	}},
	{RuleID: "env_hardcoded_secret", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{SOC2, "CC6.7", "Encryption of Data in Transit"},
		{NISTAI, "GOVERN-1.2", "Trustworthy AI characteristics"},
	}},
	{RuleID: "env_token_key", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "GOVERN-1.2", "Trustworthy AI characteristics"},
	}},
	{RuleID: "exposed_inference", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "MEASURE-2.6", "AI system monitoring"},
		{OWASPLLM, "LLM05", "Supply Chain Vulnerabilities"},
	}},
	{RuleID: "exposed_ui", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "MEASURE-2.6", "AI system monitoring"},
	}},
	{RuleID: "exposed_vector", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
		{OWASPLLM, "LLM06", "Excessive Agency"},
	}},
	{RuleID: "exposed_datastore", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
	}},
	{RuleID: "exposed_agent_runtime", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "MEASURE-2.6", "AI system monitoring"},
		{OWASPLLM, "LLM01", "Prompt Injection"},
		{OWASPLLM, "LLM06", "Excessive Agency"},
	}},
	{RuleID: "agent_auto_approve", Controls: []Control{
		{SOC2, "CC6.3", "Role-Based Access Controls"},
		{NISTAI, "MEASURE-2.6", "AI system monitoring"},
		{OWASPLLM, "LLM01", "Prompt Injection"},
		{OWASPLLM, "LLM06", "Excessive Agency"},
	}},
	{RuleID: "agent_shared_secret", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "GOVERN-1.2", "Trustworthy AI characteristics"},
	}},
	{RuleID: "agent_test_mount", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
		{OWASPLLM, "LLM06", "Excessive Agency"},
	}},
	{RuleID: "agent_auto_restart", Controls: []Control{
		{NISTAI, "MEASURE-2.6", "AI system monitoring"},
		{OWASPLLM, "LLM06", "Excessive Agency"},
	}},
	{RuleID: "permissive_cors", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{OWASPLLM, "LLM05", "Supply Chain Vulnerabilities"},
	}},
	{RuleID: "latest_image", Controls: []Control{
		{SOC2, "CC8.1", "Change Management"},
		{OWASPLLM, "LLM05", "Supply Chain Vulnerabilities"},
	}},
	{RuleID: "broad_bind_mount", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
	}},
	{RuleID: "no_internal_network", Controls: []Control{
		{SOC2, "CC6.6", "System Boundaries"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
	}},
	{RuleID: "vector_db_no_auth", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{OWASPLLM, "LLM06", "Excessive Agency"},
	}},
	{RuleID: "reverse_proxy_no_auth", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "GOVERN-1.2", "Trustworthy AI characteristics"},
	}},
	{RuleID: "dockerfile_user_root", Controls: []Control{
		{SOC2, "CC6.3", "Role-Based Access Controls"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
	}},
	{RuleID: "kube_privileged", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
	}},
	{RuleID: "kube_run_as_root", Controls: []Control{
		{SOC2, "CC6.3", "Role-Based Access Controls"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
	}},
	{RuleID: "kube_host_network", Controls: []Control{
		{SOC2, "CC6.6", "System Boundaries"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
	}},
	{RuleID: "kube_host_path", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
	}},
	{RuleID: "kube_no_network_policy", Controls: []Control{
		{SOC2, "CC6.6", "System Boundaries"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
	}},
	{RuleID: "tf_sg_ingress_all", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{SOC2, "CC6.6", "System Boundaries"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
	}},
	{RuleID: "tf_iam_admin_access", Controls: []Control{
		{SOC2, "CC6.3", "Role-Based Access Controls"},
		{NISTAI, "GOVERN-1.2", "Trustworthy AI characteristics"},
	}},
	{RuleID: "tf_s3_public_acl", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
	}},
	{RuleID: "helm_insecure_default", Controls: []Control{
		{SOC2, "CC6.1", "Logical and Physical Access Controls"},
		{NISTAI, "MAP-1.5", "AI system risk identification"},
	}},
}

func MappingIndex() map[string][]Control {
	idx := make(map[string][]Control, len(mappings))
	for _, m := range mappings {
		idx[m.RuleID] = m.Controls
	}
	return idx
}

func Frameworks() []string {
	return []string{SOC2, NISTAI, OWASPLLM}
}

func ControlsForFramework(framework string) []Control {
	seen := map[string]Control{}
	for _, m := range mappings {
		for _, c := range m.Controls {
			if c.Framework == framework {
				seen[c.ControlID] = c
			}
		}
	}
	out := make([]Control, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ControlID < out[j].ControlID
	})
	return out
}
