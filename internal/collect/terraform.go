package collect

import (
	"regexp"
	"strings"
)

// TerraformFile represents security-relevant data extracted from a .tf file.
type TerraformFile struct {
	Path           string
	SecurityGroups []TFSecurityGroup
	S3Buckets      []TFS3Bucket
	IAMPolicies    []TFIAMPolicy
	GCPFirewalls   []TFGCPFirewall
	GCPStorageACLs []TFGCPStorageACL
	AzureNSGRules  []TFAzureNSGRule
	AzureStorageAccounts []TFAzureStorageAccount
}

// TFSecurityGroup represents an AWS security group ingress/egress rule.
type TFSecurityGroup struct {
	ResourceName string
	Line         int
	Direction    string // "ingress" or "egress"
	CIDRBlocks   []string
	FromPort     string
	ToPort       string
	Protocol     string
}

// TFS3Bucket tracks S3 bucket ACL and public access settings.
type TFS3Bucket struct {
	ResourceName string
	Line         int
	ACL          string
	HasPublicBlock bool
}

// TFIAMPolicy tracks overly permissive IAM policy statements.
type TFIAMPolicy struct {
	ResourceName string
	Line         int
	Effect       string
	Actions      []string
	Resources    []string
}

// TFGCPFirewall represents a GCP compute firewall rule.
type TFGCPFirewall struct {
	ResourceName string
	Line         int
	Direction    string // "INGRESS" or "EGRESS"
	SourceRanges []string
	Ports        []string
	Protocol     string
	AllPorts     bool
}

// TFGCPStorageACL represents a GCP storage bucket ACL or IAM binding.
type TFGCPStorageACL struct {
	ResourceName string
	Line         int
	Entity       string // "allUsers", "allAuthenticatedUsers", etc.
	Member       string // IAM member string
}

// TFAzureNSGRule represents an Azure network security group rule.
type TFAzureNSGRule struct {
	ResourceName         string
	Line                 int
	Direction            string // "Inbound" or "Outbound"
	Access               string // "Allow" or "Deny"
	SourceAddressPrefix  string
	DestinationPortRange string
	Protocol             string
}

// TFAzureStorageAccount represents an Azure storage account.
type TFAzureStorageAccount struct {
	ResourceName        string
	Line                int
	AllowBlobPublicAccess bool
}

var (
	reResource     = regexp.MustCompile(`(?m)^resource\s+"(\w+)"\s+"(\w+)"\s*\{`)
	reBlock        = regexp.MustCompile(`(?m)^\s+(ingress|egress)\s*\{`)
	reCIDR         = regexp.MustCompile(`(?m)cidr_blocks\s*=\s*\[([^\]]*)\]`)
	reFromPort     = regexp.MustCompile(`(?m)from_port\s*=\s*(\d+)`)
	reToPort       = regexp.MustCompile(`(?m)to_port\s*=\s*(\d+)`)
	reProtocol     = regexp.MustCompile(`(?m)protocol\s*=\s*"([^"]*)"`)
	reACL          = regexp.MustCompile(`(?m)acl\s*=\s*"([^"]*)"`)
	reBlockPublic  = regexp.MustCompile(`(?m)block_public_acls\s*=\s*true`)
	reStatement    = regexp.MustCompile(`(?m)statement\s*\{`)
	reEffect       = regexp.MustCompile(`(?m)effect\s*=\s*"([^"]*)"`)
	reActions      = regexp.MustCompile(`(?m)actions\s*=\s*\[([^\]]*)\]`)
	reResources    = regexp.MustCompile(`(?m)resources\s*=\s*\[([^\]]*)\]`)

	// GCP
	reSourceRanges = regexp.MustCompile(`(?m)source_ranges\s*=\s*\[([^\]]*)\]`)
	reDirection    = regexp.MustCompile(`(?m)direction\s*=\s*"([^"]*)"`)
	reAllowBlock   = regexp.MustCompile(`(?m)allow\s*\{`)
	rePorts        = regexp.MustCompile(`(?m)ports\s*=\s*\[([^\]]*)\]`)
	reEntity       = regexp.MustCompile(`(?m)entity\s*=\s*"([^"]*)"`)
	reMember       = regexp.MustCompile(`(?m)member\s*=\s*"([^"]*)"`)
	reMembers      = regexp.MustCompile(`(?m)members\s*=\s*\[([^\]]*)\]`)

	// Azure
	reAccess                 = regexp.MustCompile(`(?m)access\s*=\s*"([^"]*)"`)
	reSourceAddressPrefix    = regexp.MustCompile(`(?m)source_address_prefix\s*=\s*"([^"]*)"`)
	reDestinationPortRange   = regexp.MustCompile(`(?m)destination_port_range\s*=\s*"([^"]*)"`)
	reAllowBlobPublicAccess  = regexp.MustCompile(`(?m)allow_blob_public_access\s*=\s*(true|false)`)
)

// ParseTerraformFile extracts security-relevant resources from a .tf file.
func ParseTerraformFile(path, content string) TerraformFile {
	tf := TerraformFile{Path: path}

	lines := strings.Split(content, "\n")

	matches := reResource.FindAllStringSubmatchIndex(content, -1)
	for i, loc := range matches {
		resType := content[loc[2]:loc[3]]
		resName := content[loc[4]:loc[5]]
		line := lineNumber(content, loc[0])

		end := len(content)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		block := content[loc[0]:end]

		switch resType {
		case "aws_security_group", "aws_security_group_rule":
			tf.SecurityGroups = append(tf.SecurityGroups, parseSecurityGroup(resName, line, block, lines)...)
		case "aws_s3_bucket":
			tf.S3Buckets = append(tf.S3Buckets, parseS3Bucket(resName, line, block))
		case "aws_iam_policy", "aws_iam_role_policy":
			tf.IAMPolicies = append(tf.IAMPolicies, parseIAMPolicy(resName, line, block)...)
		case "google_compute_firewall":
			tf.GCPFirewalls = append(tf.GCPFirewalls, parseGCPFirewall(resName, line, block))
		case "google_storage_bucket_access_control":
			tf.GCPStorageACLs = append(tf.GCPStorageACLs, parseGCPStorageAccessControl(resName, line, block))
		case "google_storage_bucket_iam_member":
			tf.GCPStorageACLs = append(tf.GCPStorageACLs, parseGCPStorageIAMMember(resName, line, block))
		case "google_storage_bucket_iam_binding":
			tf.GCPStorageACLs = append(tf.GCPStorageACLs, parseGCPStorageIAMBinding(resName, line, block)...)
		case "azurerm_network_security_rule":
			tf.AzureNSGRules = append(tf.AzureNSGRules, parseAzureNSGRule(resName, line, block))
		case "azurerm_storage_account":
			tf.AzureStorageAccounts = append(tf.AzureStorageAccounts, parseAzureStorageAccount(resName, line, block))
		}
	}

	return tf
}

func parseSecurityGroup(name string, baseLine int, block string, _ []string) []TFSecurityGroup {
	var groups []TFSecurityGroup

	dirMatches := reBlock.FindAllStringSubmatchIndex(block, -1)
	for _, dm := range dirMatches {
		direction := block[dm[2]:dm[3]]

		ruleEnd := len(block)
		subBlock := block[dm[0]:ruleEnd]
		closeBrace := findClosingBrace(subBlock)
		if closeBrace > 0 {
			subBlock = subBlock[:closeBrace]
		}

		sg := TFSecurityGroup{
			ResourceName: name,
			Line:         baseLine + lineNumber(block[dm[0]:], 0),
			Direction:    direction,
		}

		if m := reCIDR.FindStringSubmatch(subBlock); m != nil {
			sg.CIDRBlocks = extractQuotedStrings(m[1])
		}
		if m := reFromPort.FindStringSubmatch(subBlock); m != nil {
			sg.FromPort = m[1]
		}
		if m := reToPort.FindStringSubmatch(subBlock); m != nil {
			sg.ToPort = m[1]
		}
		if m := reProtocol.FindStringSubmatch(subBlock); m != nil {
			sg.Protocol = m[1]
		}

		groups = append(groups, sg)
	}

	return groups
}

func parseS3Bucket(name string, line int, block string) TFS3Bucket {
	b := TFS3Bucket{
		ResourceName: name,
		Line:         line,
	}
	if m := reACL.FindStringSubmatch(block); m != nil {
		b.ACL = m[1]
	}
	b.HasPublicBlock = reBlockPublic.MatchString(block)
	return b
}

func parseIAMPolicy(name string, baseLine int, block string) []TFIAMPolicy {
	var policies []TFIAMPolicy

	stmts := reStatement.FindAllStringIndex(block, -1)
	for _, s := range stmts {
		subBlock := block[s[0]:]
		closeBrace := findClosingBrace(subBlock)
		if closeBrace > 0 {
			subBlock = subBlock[:closeBrace]
		}

		p := TFIAMPolicy{
			ResourceName: name,
			Line:         baseLine + lineNumber(block[:s[0]], 0),
		}
		if m := reEffect.FindStringSubmatch(subBlock); m != nil {
			p.Effect = m[1]
		}
		if m := reActions.FindStringSubmatch(subBlock); m != nil {
			p.Actions = extractQuotedStrings(m[1])
		}
		if m := reResources.FindStringSubmatch(subBlock); m != nil {
			p.Resources = extractQuotedStrings(m[1])
		}
		policies = append(policies, p)
	}
	return policies
}

func parseGCPFirewall(name string, line int, block string) TFGCPFirewall {
	fw := TFGCPFirewall{
		ResourceName: name,
		Line:         line,
		Direction:    "INGRESS",
	}
	if m := reDirection.FindStringSubmatch(block); m != nil {
		fw.Direction = strings.ToUpper(m[1])
	}
	if m := reSourceRanges.FindStringSubmatch(block); m != nil {
		fw.SourceRanges = extractQuotedStrings(m[1])
	}
	allows := reAllowBlock.FindAllStringIndex(block, -1)
	for _, a := range allows {
		sub := block[a[0]:]
		cb := findClosingBrace(sub)
		if cb > 0 {
			sub = sub[:cb]
		}
		if m := reProtocol.FindStringSubmatch(sub); m != nil {
			fw.Protocol = m[1]
		}
		if m := rePorts.FindStringSubmatch(sub); m != nil {
			fw.Ports = append(fw.Ports, extractQuotedStrings(m[1])...)
		}
	}
	if len(allows) > 0 && len(fw.Ports) == 0 {
		fw.AllPorts = true
	}
	return fw
}

func parseGCPStorageAccessControl(name string, line int, block string) TFGCPStorageACL {
	acl := TFGCPStorageACL{
		ResourceName: name,
		Line:         line,
	}
	if m := reEntity.FindStringSubmatch(block); m != nil {
		acl.Entity = m[1]
	}
	return acl
}

func parseGCPStorageIAMMember(name string, line int, block string) TFGCPStorageACL {
	acl := TFGCPStorageACL{
		ResourceName: name,
		Line:         line,
	}
	if m := reMember.FindStringSubmatch(block); m != nil {
		acl.Member = m[1]
	}
	return acl
}

func parseGCPStorageIAMBinding(name string, line int, block string) []TFGCPStorageACL {
	var acls []TFGCPStorageACL
	if m := reMembers.FindStringSubmatch(block); m != nil {
		for _, member := range extractQuotedStrings(m[1]) {
			acls = append(acls, TFGCPStorageACL{
				ResourceName: name,
				Line:         line,
				Member:       member,
			})
		}
	}
	return acls
}

func parseAzureNSGRule(name string, line int, block string) TFAzureNSGRule {
	rule := TFAzureNSGRule{
		ResourceName: name,
		Line:         line,
	}
	if m := reDirection.FindStringSubmatch(block); m != nil {
		rule.Direction = m[1]
	}
	if m := reAccess.FindStringSubmatch(block); m != nil {
		rule.Access = m[1]
	}
	if m := reSourceAddressPrefix.FindStringSubmatch(block); m != nil {
		rule.SourceAddressPrefix = m[1]
	}
	if m := reDestinationPortRange.FindStringSubmatch(block); m != nil {
		rule.DestinationPortRange = m[1]
	}
	if m := reProtocol.FindStringSubmatch(block); m != nil {
		rule.Protocol = m[1]
	}
	return rule
}

func parseAzureStorageAccount(name string, line int, block string) TFAzureStorageAccount {
	sa := TFAzureStorageAccount{
		ResourceName: name,
		Line:         line,
	}
	if m := reAllowBlobPublicAccess.FindStringSubmatch(block); m != nil {
		sa.AllowBlobPublicAccess = m[1] == "true"
	}
	return sa
}

func lineNumber(content string, offset int) int {
	return strings.Count(content[:offset], "\n") + 1
}

func findClosingBrace(s string) int {
	depth := 0
	for i, c := range s {
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

func extractQuotedStrings(s string) []string {
	var out []string
	re := regexp.MustCompile(`"([^"]*)"`)
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}
