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
