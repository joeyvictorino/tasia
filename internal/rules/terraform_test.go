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

// --- GCP Firewall ---

func TestGCPFirewallIngressAll(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "gcp.tf",
		GCPFirewalls: []collect.TFGCPFirewall{
			{
				ResourceName: "allow_all",
				Line:         5,
				Direction:    "INGRESS",
				SourceRanges: []string{"0.0.0.0/0"},
				AllPorts:     true,
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "tf_gcp_firewall_ingress_all" {
		t.Errorf("expected tf_gcp_firewall_ingress_all, got %s", findings[0].ID)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestGCPFirewallIngressSensitive(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "gcp.tf",
		GCPFirewalls: []collect.TFGCPFirewall{
			{
				ResourceName: "ssh_open",
				Line:         10,
				Direction:    "INGRESS",
				SourceRanges: []string{"0.0.0.0/0"},
				Ports:        []string{"22"},
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "tf_gcp_firewall_ingress_sensitive" {
		t.Errorf("expected tf_gcp_firewall_ingress_sensitive, got %s", findings[0].ID)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected HIGH, got %s", findings[0].Severity)
	}
}

func TestGCPFirewallIngressWide(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "gcp.tf",
		GCPFirewalls: []collect.TFGCPFirewall{
			{
				ResourceName: "web",
				Line:         15,
				Direction:    "INGRESS",
				SourceRanges: []string{"0.0.0.0/0"},
				Ports:        []string{"443"},
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "tf_gcp_firewall_ingress_wide" {
		t.Errorf("expected tf_gcp_firewall_ingress_wide, got %s", findings[0].ID)
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("expected MEDIUM, got %s", findings[0].Severity)
	}
}

func TestGCPFirewallEgressIgnored(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "gcp.tf",
		GCPFirewalls: []collect.TFGCPFirewall{
			{
				ResourceName: "egress",
				Line:         5,
				Direction:    "EGRESS",
				SourceRanges: []string{"0.0.0.0/0"},
				AllPorts:     true,
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 0 {
		t.Fatalf("egress should not trigger, got %d", len(findings))
	}
}

func TestGCPFirewallPrivateRangeClean(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "gcp.tf",
		GCPFirewalls: []collect.TFGCPFirewall{
			{
				ResourceName: "internal",
				Line:         5,
				Direction:    "INGRESS",
				SourceRanges: []string{"10.0.0.0/8"},
				AllPorts:     true,
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 0 {
		t.Fatalf("private source range should not fire, got %d", len(findings))
	}
}

// --- GCP Storage ---

func TestGCPStoragePublicEntity(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "gcs.tf",
		GCPStorageACLs: []collect.TFGCPStorageACL{
			{ResourceName: "public_bucket", Line: 3, Entity: "allUsers"},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 || findings[0].ID != "tf_gcp_storage_public" {
		t.Fatalf("expected tf_gcp_storage_public, got %v", findings)
	}
}

func TestGCPStoragePublicIAMMember(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "gcs.tf",
		GCPStorageACLs: []collect.TFGCPStorageACL{
			{ResourceName: "iam_public", Line: 8, Member: "allUsers"},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 || findings[0].ID != "tf_gcp_storage_public" {
		t.Fatalf("expected tf_gcp_storage_public, got %v", findings)
	}
}

func TestGCPStoragePublicAuthenticatedUsers(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "gcs.tf",
		GCPStorageACLs: []collect.TFGCPStorageACL{
			{ResourceName: "auth_public", Line: 12, Entity: "allAuthenticatedUsers"},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 || findings[0].ID != "tf_gcp_storage_public" {
		t.Fatalf("expected tf_gcp_storage_public, got %v", findings)
	}
}

func TestGCPStoragePrivateClean(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "gcs.tf",
		GCPStorageACLs: []collect.TFGCPStorageACL{
			{ResourceName: "private_bucket", Line: 3, Entity: "user-admin@example.com"},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 0 {
		t.Fatalf("private entity should not fire, got %d", len(findings))
	}
}

// --- Azure NSG ---

func TestAzureNSGIngressAll(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "azure.tf",
		AzureNSGRules: []collect.TFAzureNSGRule{
			{
				ResourceName:         "allow_all",
				Line:                 5,
				Direction:            "Inbound",
				Access:               "Allow",
				SourceAddressPrefix:  "*",
				DestinationPortRange: "*",
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "tf_azure_nsg_ingress_all" {
		t.Errorf("expected tf_azure_nsg_ingress_all, got %s", findings[0].ID)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestAzureNSGIngressSensitive(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "azure.tf",
		AzureNSGRules: []collect.TFAzureNSGRule{
			{
				ResourceName:         "ssh_open",
				Line:                 10,
				Direction:            "Inbound",
				Access:               "Allow",
				SourceAddressPrefix:  "0.0.0.0/0",
				DestinationPortRange: "22",
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "tf_azure_nsg_ingress_sensitive" {
		t.Errorf("expected tf_azure_nsg_ingress_sensitive, got %s", findings[0].ID)
	}
}

func TestAzureNSGIngressWide(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "azure.tf",
		AzureNSGRules: []collect.TFAzureNSGRule{
			{
				ResourceName:         "https",
				Line:                 15,
				Direction:            "Inbound",
				Access:               "Allow",
				SourceAddressPrefix:  "Internet",
				DestinationPortRange: "443",
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "tf_azure_nsg_ingress_wide" {
		t.Errorf("expected tf_azure_nsg_ingress_wide, got %s", findings[0].ID)
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("expected MEDIUM, got %s", findings[0].Severity)
	}
}

func TestAzureNSGOutboundIgnored(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "azure.tf",
		AzureNSGRules: []collect.TFAzureNSGRule{
			{
				ResourceName:         "outbound",
				Line:                 5,
				Direction:            "Outbound",
				Access:               "Allow",
				SourceAddressPrefix:  "*",
				DestinationPortRange: "*",
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 0 {
		t.Fatalf("outbound should not trigger, got %d", len(findings))
	}
}

func TestAzureNSGDenyIgnored(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "azure.tf",
		AzureNSGRules: []collect.TFAzureNSGRule{
			{
				ResourceName:         "deny_all",
				Line:                 5,
				Direction:            "Inbound",
				Access:               "Deny",
				SourceAddressPrefix:  "*",
				DestinationPortRange: "*",
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 0 {
		t.Fatalf("deny access should not trigger, got %d", len(findings))
	}
}

// --- Azure Storage ---

func TestAzureStoragePublic(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "azure_storage.tf",
		AzureStorageAccounts: []collect.TFAzureStorageAccount{
			{ResourceName: "public_sa", Line: 3, AllowBlobPublicAccess: true},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 || findings[0].ID != "tf_azure_storage_public" {
		t.Fatalf("expected tf_azure_storage_public, got %v", findings)
	}
}

func TestAzureStoragePrivateClean(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "azure_storage.tf",
		AzureStorageAccounts: []collect.TFAzureStorageAccount{
			{ResourceName: "private_sa", Line: 3, AllowBlobPublicAccess: false},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 0 {
		t.Fatalf("private storage should not fire, got %d", len(findings))
	}
}

// --- Lambda ---

func TestLambdaAdminRole(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "lambda.tf",
		LambdaFunctions: []collect.TFLambdaFunction{
			{
				ResourceName: "admin_fn",
				Line:         5,
				Role:         "aws_iam_role.AdministratorAccess_role.arn",
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "tf_lambda_admin_role" {
		t.Errorf("expected tf_lambda_admin_role, got %s", findings[0].ID)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected HIGH, got %s", findings[0].Severity)
	}
}

func TestLambdaAdminRoleClean(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "lambda.tf",
		LambdaFunctions: []collect.TFLambdaFunction{
			{
				ResourceName: "normal_fn",
				Line:         5,
				Role:         "aws_iam_role.lambda_exec.arn",
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 0 {
		t.Fatalf("normal role should not fire, got %d", len(findings))
	}
}

func TestLambdaVPCNoSG(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "lambda.tf",
		LambdaFunctions: []collect.TFLambdaFunction{
			{
				ResourceName:     "vpc_fn",
				Line:             10,
				Role:             "aws_iam_role.exec.arn",
				VPCConfig:        true,
				SecurityGroupIDs: []string{},
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "tf_lambda_vpc_no_sg" {
		t.Errorf("expected tf_lambda_vpc_no_sg, got %s", findings[0].ID)
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("expected MEDIUM, got %s", findings[0].Severity)
	}
}

func TestLambdaVPCWithSGClean(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "lambda.tf",
		LambdaFunctions: []collect.TFLambdaFunction{
			{
				ResourceName:     "secure_fn",
				Line:             10,
				VPCConfig:        true,
				SecurityGroupIDs: []string{"sg-12345"},
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 0 {
		t.Fatalf("Lambda with SGs should not fire, got %d", len(findings))
	}
}

func TestLambdaNoVPCConfigClean(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "lambda.tf",
		LambdaFunctions: []collect.TFLambdaFunction{
			{
				ResourceName: "simple_fn",
				Line:         5,
				VPCConfig:    false,
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	if len(findings) != 0 {
		t.Fatalf("Lambda without vpc_config should not fire vpc rule, got %d", len(findings))
	}
}

// --- ECS ---

func TestECSPrivileged(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "ecs.tf",
		ECSTaskDefinitions: []collect.TFECSTaskDefinition{
			{
				ResourceName:         "priv_task",
				Line:                 3,
				ContainerDefinitions: `[{"name":"app","image":"nginx","privileged":true}]`,
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	found := false
	for _, f := range findings {
		if f.ID == "tf_ecs_privileged" {
			found = true
			if f.Severity != SeverityHigh {
				t.Errorf("expected HIGH, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected tf_ecs_privileged, got %v", findings)
	}
}

func TestECSPrivilegedClean(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "ecs.tf",
		ECSTaskDefinitions: []collect.TFECSTaskDefinition{
			{
				ResourceName:         "safe_task",
				Line:                 3,
				ContainerDefinitions: `[{"name":"app","image":"nginx"}]`,
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	for _, f := range findings {
		if f.ID == "tf_ecs_privileged" {
			t.Fatalf("should not fire on non-privileged container")
		}
	}
}

func TestECSRoot(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "ecs.tf",
		ECSTaskDefinitions: []collect.TFECSTaskDefinition{
			{
				ResourceName:         "root_task",
				Line:                 5,
				ContainerDefinitions: `[{"name":"app","image":"nginx","user":"root"}]`,
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	found := false
	for _, f := range findings {
		if f.ID == "tf_ecs_root" {
			found = true
			if f.Severity != SeverityMedium {
				t.Errorf("expected MEDIUM, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected tf_ecs_root, got %v", findings)
	}
}

func TestECSRootNumeric(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "ecs.tf",
		ECSTaskDefinitions: []collect.TFECSTaskDefinition{
			{
				ResourceName:         "root_task",
				Line:                 5,
				ContainerDefinitions: `[{"name":"app","image":"nginx","user":"0"}]`,
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	found := false
	for _, f := range findings {
		if f.ID == "tf_ecs_root" {
			found = true
		}
	}
	if !found {
		t.Fatalf("user=0 should trigger tf_ecs_root")
	}
}

func TestECSNonRootClean(t *testing.T) {
	tf := collect.TerraformFile{
		Path: "ecs.tf",
		ECSTaskDefinitions: []collect.TFECSTaskDefinition{
			{
				ResourceName:         "safe_task",
				Line:                 5,
				ContainerDefinitions: `[{"name":"app","image":"nginx","user":"appuser"}]`,
			},
		},
	}
	findings := terraformFindings([]collect.TerraformFile{tf})
	for _, f := range findings {
		if f.ID == "tf_ecs_root" {
			t.Fatalf("non-root user should not fire")
		}
	}
}
