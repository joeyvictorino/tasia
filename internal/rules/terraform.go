package rules

import (
	"fmt"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
)

func terraformFindings(files []collect.TerraformFile) []Finding {
	var out []Finding
	for _, tf := range files {
		out = append(out, sgFindings(tf)...)
		out = append(out, s3Findings(tf)...)
		out = append(out, iamFindings(tf)...)
		out = append(out, gcpFirewallFindings(tf)...)
		out = append(out, gcpStorageFindings(tf)...)
		out = append(out, azureNSGFindings(tf)...)
		out = append(out, azureStorageFindings(tf)...)
	}
	return out
}

func sgFindings(tf collect.TerraformFile) []Finding {
	var out []Finding
	for _, sg := range tf.SecurityGroups {
		if sg.Direction != "ingress" {
			continue
		}
		for _, cidr := range sg.CIDRBlocks {
			if cidr != "0.0.0.0/0" && cidr != "::/0" {
				continue
			}
			if sg.Protocol == "-1" || (sg.FromPort == "0" && sg.ToPort == "0") || (sg.FromPort == "0" && sg.ToPort == "65535") {
				out = append(out, Finding{
					ID:       "tf_sg_ingress_all",
					Severity: SeverityCritical,
					Title:    "Security group allows all inbound traffic",
					File:     tf.Path,
					Line:     sg.Line,
					Evidence: fmt.Sprintf("cidr_blocks includes %s with protocol=%s ports=%s-%s", cidr, sg.Protocol, sg.FromPort, sg.ToPort),
					Why:      "Unrestricted inbound access exposes every port to the internet",
					Fix:      "Restrict cidr_blocks to known IPs and limit port ranges",
				})
			} else if isSensitivePort(sg.FromPort) || isSensitivePort(sg.ToPort) {
				out = append(out, Finding{
					ID:       "tf_sg_ingress_sensitive",
					Severity: SeverityHigh,
					Title:    "Security group exposes sensitive port to internet",
					File:     tf.Path,
					Line:     sg.Line,
					Evidence: fmt.Sprintf("cidr_blocks includes %s on port %s-%s", cidr, sg.FromPort, sg.ToPort),
					Why:      "Database, SSH, or admin ports open to 0.0.0.0/0 invite brute-force and exploitation",
					Fix:      "Restrict ingress to known IPs or use a bastion/VPN",
				})
			} else {
				out = append(out, Finding{
					ID:       "tf_sg_ingress_wide",
					Severity: SeverityMedium,
					Title:    "Security group allows internet ingress",
					File:     tf.Path,
					Line:     sg.Line,
					Evidence: fmt.Sprintf("cidr_blocks includes %s on port %s-%s", cidr, sg.FromPort, sg.ToPort),
					Why:      "Ingress from 0.0.0.0/0 should be intentional and minimized",
					Fix:      "Verify this port must be public; restrict if not",
				})
			}
		}
	}
	return out
}

func isSensitivePort(port string) bool {
	switch port {
	case "22", "3306", "5432", "6379", "27017", "9200", "2375", "2376", "5900", "3389":
		return true
	}
	return false
}

func s3Findings(tf collect.TerraformFile) []Finding {
	var out []Finding
	for _, b := range tf.S3Buckets {
		if b.ACL == "public-read" || b.ACL == "public-read-write" {
			out = append(out, Finding{
				ID:       "tf_s3_public_acl",
				Severity: SeverityHigh,
				Title:    "S3 bucket with public ACL",
				File:     tf.Path,
				Line:     b.Line,
				Evidence: fmt.Sprintf("acl = %q on %s", b.ACL, b.ResourceName),
				Why:      "Public S3 buckets are a top source of data leaks",
				Fix:      "Set acl = \"private\" and add an aws_s3_bucket_public_access_block",
			})
		}
	}
	return out
}

func gcpFirewallFindings(tf collect.TerraformFile) []Finding {
	var out []Finding
	for _, fw := range tf.GCPFirewalls {
		if !strings.EqualFold(fw.Direction, "INGRESS") {
			continue
		}
		for _, src := range fw.SourceRanges {
			if src != "0.0.0.0/0" && src != "::/0" {
				continue
			}
			if fw.AllPorts {
				out = append(out, Finding{
					ID:       "tf_gcp_firewall_ingress_all",
					Severity: SeverityCritical,
					Title:    "GCP firewall allows all inbound traffic",
					File:     tf.Path,
					Line:     fw.Line,
					Evidence: fmt.Sprintf("source_ranges includes %s with all ports on %s", src, fw.ResourceName),
					Why:      "Unrestricted inbound access exposes every port to the internet",
					Fix:      "Restrict source_ranges to known IPs and specify allowed ports",
				})
			} else if gcpHasSensitivePort(fw.Ports) {
				out = append(out, Finding{
					ID:       "tf_gcp_firewall_ingress_sensitive",
					Severity: SeverityHigh,
					Title:    "GCP firewall exposes sensitive port to internet",
					File:     tf.Path,
					Line:     fw.Line,
					Evidence: fmt.Sprintf("source_ranges includes %s on ports %v", src, fw.Ports),
					Why:      "Database, SSH, or admin ports open to 0.0.0.0/0 invite brute-force and exploitation",
					Fix:      "Restrict source_ranges to known IPs or use IAP/VPN",
				})
			} else {
				out = append(out, Finding{
					ID:       "tf_gcp_firewall_ingress_wide",
					Severity: SeverityMedium,
					Title:    "GCP firewall allows internet ingress",
					File:     tf.Path,
					Line:     fw.Line,
					Evidence: fmt.Sprintf("source_ranges includes %s on ports %v", src, fw.Ports),
					Why:      "Ingress from 0.0.0.0/0 should be intentional and minimized",
					Fix:      "Verify this port must be public; restrict if not",
				})
			}
		}
	}
	return out
}

func gcpHasSensitivePort(ports []string) bool {
	for _, p := range ports {
		if isSensitivePort(p) {
			return true
		}
	}
	return false
}

func gcpStorageFindings(tf collect.TerraformFile) []Finding {
	var out []Finding
	for _, acl := range tf.GCPStorageACLs {
		public := false
		detail := ""
		if acl.Entity != "" {
			e := strings.ToLower(acl.Entity)
			if strings.Contains(e, "allusers") || strings.Contains(e, "allauthenticatedusers") {
				public = true
				detail = fmt.Sprintf("entity = %q on %s", acl.Entity, acl.ResourceName)
			}
		}
		if acl.Member != "" {
			m := strings.ToLower(acl.Member)
			if m == "allusers" || m == "allauthenticatedusers" {
				public = true
				detail = fmt.Sprintf("member = %q on %s", acl.Member, acl.ResourceName)
			}
		}
		if public {
			out = append(out, Finding{
				ID:       "tf_gcp_storage_public",
				Severity: SeverityHigh,
				Title:    "GCP storage bucket with public access",
				File:     tf.Path,
				Line:     acl.Line,
				Evidence: detail,
				Why:      "Public storage buckets are a top source of data leaks",
				Fix:      "Remove allUsers/allAuthenticatedUsers and use IAM for access control",
			})
		}
	}
	return out
}

func azureNSGFindings(tf collect.TerraformFile) []Finding {
	var out []Finding
	for _, rule := range tf.AzureNSGRules {
		if !strings.EqualFold(rule.Direction, "Inbound") {
			continue
		}
		if !strings.EqualFold(rule.Access, "Allow") {
			continue
		}
		src := rule.SourceAddressPrefix
		if src != "*" && src != "0.0.0.0/0" && src != "Internet" {
			continue
		}
		port := rule.DestinationPortRange
		if port == "*" {
			out = append(out, Finding{
				ID:       "tf_azure_nsg_ingress_all",
				Severity: SeverityCritical,
				Title:    "Azure NSG allows all inbound traffic",
				File:     tf.Path,
				Line:     rule.Line,
				Evidence: fmt.Sprintf("source_address_prefix = %q destination_port_range = %q on %s", src, port, rule.ResourceName),
				Why:      "Unrestricted inbound access exposes every port to the internet",
				Fix:      "Restrict source_address_prefix to known IPs and limit port ranges",
			})
		} else if isSensitivePort(port) {
			out = append(out, Finding{
				ID:       "tf_azure_nsg_ingress_sensitive",
				Severity: SeverityHigh,
				Title:    "Azure NSG exposes sensitive port to internet",
				File:     tf.Path,
				Line:     rule.Line,
				Evidence: fmt.Sprintf("source_address_prefix = %q destination_port_range = %q on %s", src, port, rule.ResourceName),
				Why:      "Database, SSH, or admin ports open to the internet invite brute-force and exploitation",
				Fix:      "Restrict source_address_prefix to known IPs or use a bastion/VPN",
			})
		} else {
			out = append(out, Finding{
				ID:       "tf_azure_nsg_ingress_wide",
				Severity: SeverityMedium,
				Title:    "Azure NSG allows internet ingress",
				File:     tf.Path,
				Line:     rule.Line,
				Evidence: fmt.Sprintf("source_address_prefix = %q destination_port_range = %q on %s", src, port, rule.ResourceName),
				Why:      "Ingress from the internet should be intentional and minimized",
				Fix:      "Verify this port must be public; restrict if not",
			})
		}
	}
	return out
}

func azureStorageFindings(tf collect.TerraformFile) []Finding {
	var out []Finding
	for _, sa := range tf.AzureStorageAccounts {
		if sa.AllowBlobPublicAccess {
			out = append(out, Finding{
				ID:       "tf_azure_storage_public",
				Severity: SeverityHigh,
				Title:    "Azure storage account allows public blob access",
				File:     tf.Path,
				Line:     sa.Line,
				Evidence: fmt.Sprintf("allow_blob_public_access = true on %s", sa.ResourceName),
				Why:      "Public blob access can expose sensitive data to the internet",
				Fix:      "Set allow_blob_public_access = false",
			})
		}
	}
	return out
}

func iamFindings(tf collect.TerraformFile) []Finding {
	var out []Finding
	for _, p := range tf.IAMPolicies {
		if !strings.EqualFold(p.Effect, "Allow") {
			continue
		}
		hasStarAction := false
		for _, a := range p.Actions {
			if a == "*" {
				hasStarAction = true
				break
			}
		}
		hasStarResource := false
		for _, r := range p.Resources {
			if r == "*" {
				hasStarResource = true
				break
			}
		}
		if hasStarAction && hasStarResource {
			out = append(out, Finding{
				ID:       "tf_iam_admin_access",
				Severity: SeverityCritical,
				Title:    "IAM policy grants unrestricted admin access",
				File:     tf.Path,
				Line:     p.Line,
				Evidence: fmt.Sprintf("Effect=Allow actions=[\"*\"] resources=[\"*\"] on %s", p.ResourceName),
				Why:      "A policy with Action:* Resource:* is equivalent to full AWS account access",
				Fix:      "Follow least-privilege: scope actions and resources to what is needed",
			})
		} else if hasStarAction {
			out = append(out, Finding{
				ID:       "tf_iam_star_actions",
				Severity: SeverityHigh,
				Title:    "IAM policy grants all actions",
				File:     tf.Path,
				Line:     p.Line,
				Evidence: fmt.Sprintf("Effect=Allow actions=[\"*\"] on %s", p.ResourceName),
				Why:      "Wildcard actions grant every API call regardless of resource scope",
				Fix:      "Enumerate only the actions the workload needs",
			})
		}
	}
	return out
}
