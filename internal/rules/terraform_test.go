package rules

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
)

func TestTFSecurityGroupIngressAll(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "main.tf",
		SecurityGroups: []collect.TFSecurityGroup{
			{
				ResourceName: "allow_all",
				Line:         10,
				Direction:    "ingress",
				CIDRBlocks:   []string{"0.0.0.0/0"},
				FromPort:     "0",
				ToPort:       "65535",
				Protocol:     "tcp",
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "tf_sg_ingress_all" {
		t.Errorf("expected tf_sg_ingress_all, got %s", findings[0].ID)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestTFSecurityGroupIngressSensitive(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "main.tf",
		SecurityGroups: []collect.TFSecurityGroup{
			{
				ResourceName: "ssh_open",
				Line:         15,
				Direction:    "ingress",
				CIDRBlocks:   []string{"0.0.0.0/0"},
				FromPort:     "22",
				ToPort:       "22",
				Protocol:     "tcp",
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "tf_sg_ingress_sensitive" {
		t.Errorf("expected tf_sg_ingress_sensitive, got %s", findings[0].ID)
	}
}

func TestTFSecurityGroupIngressWide(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "main.tf",
		SecurityGroups: []collect.TFSecurityGroup{
			{
				ResourceName: "web",
				Line:         20,
				Direction:    "ingress",
				CIDRBlocks:   []string{"0.0.0.0/0"},
				FromPort:     "443",
				ToPort:       "443",
				Protocol:     "tcp",
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "tf_sg_ingress_wide" {
		t.Errorf("expected tf_sg_ingress_wide, got %s", findings[0].ID)
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("expected MEDIUM, got %s", findings[0].Severity)
	}
}

func TestTFSecurityGroupEgressIgnored(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "main.tf",
		SecurityGroups: []collect.TFSecurityGroup{
			{
				ResourceName: "egress_all",
				Line:         5,
				Direction:    "egress",
				CIDRBlocks:   []string{"0.0.0.0/0"},
				FromPort:     "0",
				ToPort:       "65535",
				Protocol:     "-1",
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 0 {
		t.Fatalf("egress should not trigger ingress rules, got %d findings", len(findings))
	}
}

func TestTFS3PublicACL(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "storage.tf",
		S3Buckets: []collect.TFS3Bucket{
			{ResourceName: "data_bucket", Line: 1, ACL: "public-read"},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 || findings[0].ID != "tf_s3_public_acl" {
		t.Fatalf("expected tf_s3_public_acl, got %v", findings)
	}
}

func TestTFS3PrivateACLClean(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "storage.tf",
		S3Buckets: []collect.TFS3Bucket{
			{ResourceName: "data_bucket", Line: 1, ACL: "private"},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 0 {
		t.Fatalf("private ACL should not fire, got %d", len(findings))
	}
}

func TestTFIAMAdminAccess(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "iam.tf",
		IAMPolicies: []collect.TFIAMPolicy{
			{
				ResourceName: "admin",
				Line:         5,
				Effect:       "Allow",
				Actions:      []string{"*"},
				Resources:    []string{"*"},
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 || findings[0].ID != "tf_iam_admin_access" {
		t.Fatalf("expected tf_iam_admin_access, got %v", findings)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestTFIAMStarActions(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "iam.tf",
		IAMPolicies: []collect.TFIAMPolicy{
			{
				ResourceName: "wide",
				Line:         10,
				Effect:       "Allow",
				Actions:      []string{"*"},
				Resources:    []string{"arn:aws:s3:::my-bucket"},
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 || findings[0].ID != "tf_iam_star_actions" {
		t.Fatalf("expected tf_iam_star_actions, got %v", findings)
	}
}

func TestTFIAMDenyIgnored(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "iam.tf",
		IAMPolicies: []collect.TFIAMPolicy{
			{
				ResourceName: "deny_all",
				Line:         1,
				Effect:       "Deny",
				Actions:      []string{"*"},
				Resources:    []string{"*"},
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 0 {
		t.Fatalf("Deny effect should not fire, got %d", len(findings))
	}
}
