package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseTerraformSecurityGroup(t *testing.T) {
	content := `
resource "aws_security_group" "allow_all" {
  name = "allow-all"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
	tf := ParseTerraformFile("main.tf", content)
	if len(tf.SecurityGroups) != 2 {
		t.Fatalf("expected 2 security groups (ingress+egress), got %d", len(tf.SecurityGroups))
	}
	ingress := tf.SecurityGroups[0]
	if ingress.Direction != "ingress" {
		t.Errorf("first group direction = %q, want ingress", ingress.Direction)
	}
	if len(ingress.CIDRBlocks) != 1 || ingress.CIDRBlocks[0] != "0.0.0.0/0" {
		t.Errorf("CIDR blocks = %v", ingress.CIDRBlocks)
	}
	if ingress.FromPort != "0" || ingress.ToPort != "65535" {
		t.Errorf("ports = %s-%s", ingress.FromPort, ingress.ToPort)
	}
}

func TestParseTerraformS3Public(t *testing.T) {
	content := `
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}
`
	tf := ParseTerraformFile("s3.tf", content)
	if len(tf.S3Buckets) != 1 {
		t.Fatalf("expected 1 S3 bucket, got %d", len(tf.S3Buckets))
	}
	if tf.S3Buckets[0].ACL != "public-read" {
		t.Errorf("ACL = %q, want public-read", tf.S3Buckets[0].ACL)
	}
}

func TestParseTerraformIAMStarStar(t *testing.T) {
	content := `
resource "aws_iam_policy" "admin" {
  name = "admin-access"
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })

  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}
`
	tf := ParseTerraformFile("iam.tf", content)
	if len(tf.IAMPolicies) != 1 {
		t.Fatalf("expected 1 IAM policy statement, got %d", len(tf.IAMPolicies))
	}
	p := tf.IAMPolicies[0]
	if p.Effect != "Allow" {
		t.Errorf("effect = %q", p.Effect)
	}
	if len(p.Actions) != 1 || p.Actions[0] != "*" {
		t.Errorf("actions = %v", p.Actions)
	}
}

func TestWalkCollectsTerraformFiles(t *testing.T) {
	tmp := t.TempDir()
	content := `
resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
	if err := os.WriteFile(filepath.Join(tmp, "main.tf"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	col, err := WalkAndCollect(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(col.TerraformFiles) != 1 {
		t.Fatalf("expected 1 terraform file, got %d", len(col.TerraformFiles))
	}
	if len(col.TerraformFiles[0].SecurityGroups) != 1 {
		t.Errorf("expected 1 security group from walk, got %d", len(col.TerraformFiles[0].SecurityGroups))
	}
}

func TestParseTerraformLambda(t *testing.T) {
	content := `
resource "aws_lambda_function" "admin_fn" {
  function_name = "admin-fn"
  role          = aws_iam_role.AdministratorAccess_role.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"

  vpc_config {
    subnet_ids         = ["subnet-123"]
    security_group_ids = []
  }
}
`
	tf := ParseTerraformFile("lambda.tf", content)
	if len(tf.LambdaFunctions) != 1 {
		t.Fatalf("expected 1 lambda, got %d", len(tf.LambdaFunctions))
	}
	lf := tf.LambdaFunctions[0]
	if lf.ResourceName != "admin_fn" {
		t.Errorf("name: got %q", lf.ResourceName)
	}
	if !lf.VPCConfig {
		t.Error("expected VPCConfig=true")
	}
	if len(lf.SecurityGroupIDs) != 0 {
		t.Errorf("expected empty security_group_ids, got %v", lf.SecurityGroupIDs)
	}
	if lf.Role == "" {
		t.Error("expected role to be set")
	}
}

func TestParseTerraformLambdaWithSGs(t *testing.T) {
	content := `
resource "aws_lambda_function" "secure_fn" {
  function_name = "secure-fn"
  role          = aws_iam_role.exec.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"

  vpc_config {
    subnet_ids         = ["subnet-123"]
    security_group_ids = ["sg-abc123"]
  }
}
`
	tf := ParseTerraformFile("lambda.tf", content)
	if len(tf.LambdaFunctions) != 1 {
		t.Fatalf("expected 1 lambda, got %d", len(tf.LambdaFunctions))
	}
	lf := tf.LambdaFunctions[0]
	if len(lf.SecurityGroupIDs) != 1 || lf.SecurityGroupIDs[0] != "sg-abc123" {
		t.Errorf("expected [sg-abc123], got %v", lf.SecurityGroupIDs)
	}
}

func TestParseTerraformECS(t *testing.T) {
	content := `
resource "aws_ecs_task_definition" "priv_task" {
  family = "app"
  container_definitions = <<EOF
[{"name":"app","image":"nginx","privileged":true,"user":"root"}]
EOF
}
`
	tf := ParseTerraformFile("ecs.tf", content)
	if len(tf.ECSTaskDefinitions) != 1 {
		t.Fatalf("expected 1 ECS task def, got %d", len(tf.ECSTaskDefinitions))
	}
	td := tf.ECSTaskDefinitions[0]
	if td.ResourceName != "priv_task" {
		t.Errorf("name: got %q", td.ResourceName)
	}
	if td.ContainerDefinitions == "" {
		t.Error("expected container_definitions to be captured")
	}
}

func TestParseTerraformIAMRolePolicyAttachment(t *testing.T) {
	content := `
resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
`
	tf := ParseTerraformFile("iam.tf", content)
	if len(tf.IAMPolicies) != 1 {
		t.Fatalf("expected 1 IAM policy from attachment, got %d", len(tf.IAMPolicies))
	}
	p := tf.IAMPolicies[0]
	if len(p.Actions) != 1 || p.Actions[0] != "*" {
		t.Errorf("expected actions=[*] for AdministratorAccess, got %v", p.Actions)
	}
}
