# =============================================================================
# Lambda@Edge module
#
# Provisions three CloudFront-associated Lambda@Edge functions in us-east-1
# (the only region from which Lambda@Edge replication is supported):
#
#   1. security-headers   -> viewer-response   -> hardens response headers
#   2. geo-router         -> origin-request    -> routes by viewer country
#   3. header-rewrite     -> viewer-request    -> strips & injects headers
#
# Each function is packaged from a sibling directory under ../../../lambda-edge
# using the `archive_file` data source and uploaded directly (no S3 object).
# Lambda@Edge requires:
#   - Provider alias pointing at us-east-1
#   - `publish = true` so a numeric version exists
#   - Trust policy that allows both lambda + edgelambda principals to assume
#   - No environment variables on the function (Lambda@Edge restriction)
# =============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 5.0"
      configuration_aliases = [aws.us_east_1]
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Source bundles
# -----------------------------------------------------------------------------
data "archive_file" "security_headers" {
  type        = "zip"
  source_dir  = "${path.module}/../../../lambda-edge/security-headers"
  output_path = "${path.module}/.build/security-headers.zip"
}

data "archive_file" "geo_router" {
  type        = "zip"
  source_dir  = "${path.module}/../../../lambda-edge/geo-router"
  output_path = "${path.module}/.build/geo-router.zip"
}

data "archive_file" "header_rewrite" {
  type        = "zip"
  source_dir  = "${path.module}/../../../lambda-edge/header-rewrite"
  output_path = "${path.module}/.build/header-rewrite.zip"
}

# -----------------------------------------------------------------------------
# Shared execution role
# Lambda@Edge requires *both* lambda.amazonaws.com and edgelambda.amazonaws.com
# in the trust policy.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "lambda.amazonaws.com",
        "edgelambda.amazonaws.com"
      ]
    }
  }
}

resource "aws_iam_role" "edge" {
  provider           = aws.us_east_1
  name               = "${var.name_prefix}-edge-exec"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  tags               = var.tags
}

# Lambda@Edge logs in *every* edge region's CloudWatch Logs - we need the
# AWSLambdaBasicExecutionRole equivalent for all of them. The managed policy
# covers that.
resource "aws_iam_role_policy_attachment" "edge_basic" {
  provider   = aws.us_east_1
  role       = aws_iam_role.edge.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# -----------------------------------------------------------------------------
# Function: security-headers
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "security_headers" {
  provider = aws.us_east_1

  function_name = "${var.name_prefix}-security-headers"
  role          = aws_iam_role.edge.arn
  runtime       = "nodejs18.x"
  handler       = "index.handler"
  filename      = data.archive_file.security_headers.output_path
  source_code_hash = data.archive_file.security_headers.output_base64sha256

  # Lambda@Edge limits: viewer-* functions max 5s, 128 MB.
  memory_size = 128
  timeout     = 5

  publish = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-security-headers"
    Edge = "viewer-response"
  })
}

# -----------------------------------------------------------------------------
# Function: geo-router
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "geo_router" {
  provider = aws.us_east_1

  function_name = "${var.name_prefix}-geo-router"
  role          = aws_iam_role.edge.arn
  runtime       = "nodejs18.x"
  handler       = "index.handler"
  filename      = data.archive_file.geo_router.output_path
  source_code_hash = data.archive_file.geo_router.output_base64sha256

  # origin-request can use up to 30s and 10 GB; we stay tight.
  memory_size = 128
  timeout     = 5

  publish = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-geo-router"
    Edge = "origin-request"
  })
}

# -----------------------------------------------------------------------------
# Function: header-rewrite
# -----------------------------------------------------------------------------
resource "aws_lambda_function" "header_rewrite" {
  provider = aws.us_east_1

  function_name = "${var.name_prefix}-header-rewrite"
  role          = aws_iam_role.edge.arn
  runtime       = "nodejs18.x"
  handler       = "index.handler"
  filename      = data.archive_file.header_rewrite.output_path
  source_code_hash = data.archive_file.header_rewrite.output_base64sha256

  memory_size = 128
  timeout     = 5

  publish = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-header-rewrite"
    Edge = "viewer-request"
  })
}

# -----------------------------------------------------------------------------
# CloudWatch log group retention - logs land in each edge region but we can
# at least pre-create the primary one with a sensible retention.
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "security_headers" {
  provider          = aws.us_east_1
  name              = "/aws/lambda/us-east-1.${aws_lambda_function.security_headers.function_name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "geo_router" {
  provider          = aws.us_east_1
  name              = "/aws/lambda/us-east-1.${aws_lambda_function.geo_router.function_name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "header_rewrite" {
  provider          = aws.us_east_1
  name              = "/aws/lambda/us-east-1.${aws_lambda_function.header_rewrite.function_name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}
