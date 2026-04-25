###############################################################################
# Terraform & provider version pins.
#
# CloudFront, WAFv2 (CLOUDFRONT scope), ACM certs for CloudFront, and
# Lambda@Edge ALL must live in us-east-1, regardless of where the rest of the
# stack runs. We therefore expose an `aws.us_east_1` aliased provider that
# downstream modules use whenever they need a us-east-1-only resource.
###############################################################################

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# Primary provider — used for "regional" resources that may live anywhere
# (S3 origin buckets, log buckets, Firehose, Glue, etc.).
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge({
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Repository  = "aws-edge-security-platform"
      Owner       = "platform-security"
    }, var.extra_tags)
  }
}

# us-east-1 alias — REQUIRED for CloudFront, WAFv2 CLOUDFRONT scope, ACM
# certificates referenced by CloudFront, and Lambda@Edge functions.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = merge({
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Repository  = "aws-edge-security-platform"
      Owner       = "platform-security"
    }, var.extra_tags)
  }
}
