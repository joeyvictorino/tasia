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
