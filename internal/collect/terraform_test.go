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
