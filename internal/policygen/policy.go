package policygen

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/joeyvictorino/tasia/internal/rules"
)

type Requirement struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Evidence    string `json:"evidence"`
}

type PolicySection struct {
	Title        string        `json:"title"`
	Description  string        `json:"description"`
	Requirements []Requirement `json:"requirements"`
	Status       string        `json:"status"`
}

type PolicyDocument struct {
	Title       string          `json:"title"`
	GeneratedAt string          `json:"generated_at"`
	ScanPath    string          `json:"scan_path"`
	Summary     PolicySummary   `json:"summary"`
	Sections    []PolicySection `json:"sections"`
}

type PolicySummary struct {
	TotalRequirements int     `json:"total_requirements"`
	Compliant         int     `json:"compliant"`
	NonCompliant      int     `json:"non_compliant"`
	Partial           int     `json:"partial"`
	ScorePct          float64 `json:"score_pct"`
}

type sectionDef struct {
	Title       string
	Description string
	Rules       []string
}

var sections = []sectionDef{
	{
		Title:       "Container Security",
		Description: "Controls for container isolation, privilege restrictions, and image integrity.",
		Rules:       []string{"docker_socket_mount", "privileged_container", "latest_image", "broad_bind_mount", "dockerfile_user_root", "kube_privileged", "kube_run_as_root", "tf_ecs_privileged", "tf_ecs_root"},
	},
	{
		Title:       "Network Security",
		Description: "Controls for network segmentation, exposure minimization, and firewall rules.",
		Rules:       []string{"exposed_inference", "exposed_ui", "exposed_vector", "exposed_datastore", "exposed_agent_runtime", "no_internal_network", "permissive_cors", "kube_exposed_service", "kube_host_network", "kube_no_network_policy", "kube_host_path", "tf_sg_ingress_all", "tf_sg_ingress_sensitive", "tf_sg_ingress_wide", "tf_gcp_firewall_ingress_all", "tf_gcp_firewall_ingress_sensitive", "tf_gcp_firewall_ingress_wide", "tf_azure_nsg_ingress_all", "tf_azure_nsg_ingress_sensitive", "tf_azure_nsg_ingress_wide"},
	},
	{
		Title:       "Secret Management",
		Description: "Controls for secret storage, rotation, and prevention of credential leakage.",
		Rules:       []string{"env_token_key", "env_hardcoded_secret", "agent_shared_secret"},
	},
	{
		Title:       "Authentication & Authorization",
		Description: "Controls for authentication enforcement and access control.",
		Rules:       []string{"vector_db_no_auth", "reverse_proxy_no_auth", "tf_iam_admin_access", "tf_iam_star_actions", "tf_lambda_admin_role"},
	},
	{
		Title:       "Agent Runtime Safety",
		Description: "Controls for agent execution boundaries, auto-approval, and restart behavior.",
		Rules:       []string{"agent_auto_approve", "agent_test_mount", "agent_auto_restart"},
	},
	{
		Title:       "Data Store Security",
		Description: "Controls for data store access, public exposure, and storage permissions.",
		Rules:       []string{"tf_s3_public_acl", "tf_gcp_storage_public", "tf_azure_storage_public"},
	},
	{
		Title:       "Infrastructure as Code",
		Description: "Controls for IaC security defaults, Helm chart hardening, and Lambda/VPC configuration.",
		Rules:       []string{"helm_insecure_default", "tf_lambda_vpc_no_sg", "no_ai_stack_manifest", "dockerfile_expose", "dockerfile_expose_sensitive"},
	},
}

func GeneratePolicy(title, scanPath string, findings []rules.Finding) PolicyDocument {
	findingsByRule := map[string][]rules.Finding{}
	for _, f := range findings {
		findingsByRule[f.ID] = append(findingsByRule[f.ID], f)
	}

	catalog := rules.CatalogMap()

	doc := PolicyDocument{
		Title:       title,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		ScanPath:    scanPath,
	}

	totalReqs := 0
	compliant := 0
	nonCompliant := 0

	for _, sd := range sections {
		sec := PolicySection{
			Title:       sd.Title,
			Description: sd.Description,
		}

		sectionCompliant := 0
		sectionNonCompliant := 0

		for _, ruleID := range sd.Rules {
			info, ok := catalog[ruleID]
			if !ok {
				continue
			}

			req := Requirement{
				ID:          ruleID,
				Description: info.Title,
			}

			if ff, found := findingsByRule[ruleID]; found && len(ff) > 0 {
				req.Status = "non_compliant"
				var evParts []string
				for _, f := range ff {
					evParts = append(evParts, fmt.Sprintf("%s:%d", f.File, f.Line))
				}
				req.Evidence = fmt.Sprintf("%d finding(s): %s", len(ff), strings.Join(evParts, ", "))
				sectionNonCompliant++
			} else {
				req.Status = "compliant"
				req.Evidence = "No findings detected"
				sectionCompliant++
			}

			sec.Requirements = append(sec.Requirements, req)
			totalReqs++
		}

		if sectionNonCompliant == 0 {
			sec.Status = "compliant"
			compliant += sectionCompliant
		} else if sectionCompliant == 0 {
			sec.Status = "non_compliant"
			nonCompliant += sectionNonCompliant
		} else {
			sec.Status = "partial"
			compliant += sectionCompliant
			nonCompliant += sectionNonCompliant
		}

		doc.Sections = append(doc.Sections, sec)
	}

	scorePct := 0.0
	if totalReqs > 0 {
		scorePct = float64(compliant) / float64(totalReqs) * 100
	}
	doc.Summary = PolicySummary{
		TotalRequirements: totalReqs,
		Compliant:         compliant,
		NonCompliant:      nonCompliant,
		Partial:           countPartial(doc.Sections),
		ScorePct:          scorePct,
	}

	return doc
}

func countPartial(secs []PolicySection) int {
	n := 0
	for _, s := range secs {
		if s.Status == "partial" {
			n++
		}
	}
	return n
}

func FormatMarkdown(doc PolicyDocument) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# %s\n\n", doc.Title))
	b.WriteString(fmt.Sprintf("**Generated:** %s  \n", doc.GeneratedAt))
	b.WriteString(fmt.Sprintf("**Scan Path:** %s  \n", doc.ScanPath))
	b.WriteString(fmt.Sprintf("**Compliance Score:** %.1f%% (%d/%d requirements met)\n\n",
		doc.Summary.ScorePct, doc.Summary.Compliant, doc.Summary.TotalRequirements))

	b.WriteString("---\n\n")

	for _, sec := range doc.Sections {
		badge := "PASS"
		if sec.Status == "non_compliant" {
			badge = "FAIL"
		} else if sec.Status == "partial" {
			badge = "PARTIAL"
		}
		b.WriteString(fmt.Sprintf("## %s [%s]\n\n", sec.Title, badge))
		b.WriteString(fmt.Sprintf("%s\n\n", sec.Description))

		for _, req := range sec.Requirements {
			mark := "x"
			if req.Status != "compliant" {
				mark = " "
			}
			b.WriteString(fmt.Sprintf("- [%s] **%s** (`%s`)\n", mark, req.Description, req.ID))
			b.WriteString(fmt.Sprintf("  - %s\n", req.Evidence))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func FormatText(doc PolicyDocument) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s\n", doc.Title))
	b.WriteString(strings.Repeat("=", len(doc.Title)) + "\n\n")
	b.WriteString(fmt.Sprintf("Generated: %s\n", doc.GeneratedAt))
	b.WriteString(fmt.Sprintf("Scan Path: %s\n", doc.ScanPath))
	b.WriteString(fmt.Sprintf("Score:     %.1f%% (%d/%d)\n\n",
		doc.Summary.ScorePct, doc.Summary.Compliant, doc.Summary.TotalRequirements))

	for _, sec := range doc.Sections {
		status := strings.ToUpper(sec.Status)
		b.WriteString(fmt.Sprintf("  %s [%s]\n", sec.Title, status))
		for _, req := range sec.Requirements {
			icon := "+"
			if req.Status != "compliant" {
				icon = "-"
			}
			b.WriteString(fmt.Sprintf("    %s %-40s %s\n", icon, req.Description, req.Evidence))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func SectionTitles() []string {
	out := make([]string, len(sections))
	for i, s := range sections {
		out[i] = s.Title
	}
	sort.Strings(out)
	return out
}
