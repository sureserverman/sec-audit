terraform {
  required_version = ">= 1.0"
}

# CWE-798: hardcoded AWS credentials in provider block.
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# CWE-732: S3 bucket with public-read ACL.
resource "aws_s3_bucket" "exposed" {
  bucket = "my-vulnerable-bucket"
}

resource "aws_s3_bucket_acl" "exposed" {
  bucket = aws_s3_bucket.exposed.id
  acl    = "public-read"
}

# CWE-732: IAM policy with wildcard action + resource.
resource "aws_iam_policy" "wildcard" {
  name   = "allow-everything"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# CWE-284: security group allowing SSH from 0.0.0.0/0.
resource "aws_security_group" "open_ssh" {
  name = "open-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# CWE-311: RDS instance without storage_encrypted.
resource "aws_db_instance" "unencrypted" {
  identifier        = "vulnerable-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  # storage_encrypted intentionally absent.
  username = "admin"
  password = "notverysecret"
}

# CWE-532: variable for secret without sensitive = true.
variable "api_token" {
  type        = string
  description = "API token for downstream service"
  # intentionally missing: sensitive = true
}

# CWE-312: remote state backend without encryption.
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "path/to/state"
    region = "us-east-1"
    # encrypt = true intentionally absent
  }
}
