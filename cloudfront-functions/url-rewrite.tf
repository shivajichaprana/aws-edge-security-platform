# =============================================================================
# CloudFront Function - URL Rewrite
#
# Deploys the url-rewrite.js function as an aws_cloudfront_function resource.
# CloudFront Functions are NOT Lambda@Edge - they run in a hardened V8
# sandbox at every edge POP with a sub-millisecond execution budget. Use
# them for header/URL manipulation; use Lambda@Edge for anything heavier.
#
# Association with a distribution is done in the cloudfront module via the
# `function_association` block, referencing this resource's ARN.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "name_prefix" {
  description = "Prefix applied to the CloudFront Function name."
  type        = string
}

variable "publish" {
  description = "Whether to publish the function on apply (DEVELOPMENT vs LIVE stage)."
  type        = bool
  default     = true
}

resource "aws_cloudfront_function" "url_rewrite" {
  name    = "${var.name_prefix}-url-rewrite"
  runtime = "cloudfront-js-2.0"
  comment = "Lightweight URL normalisation: directory index, .html suffix, legacy /api/v0 rewrite."
  publish = var.publish
  code    = file("${path.module}/url-rewrite.js")
}

output "function_arn" {
  description = "ARN of the published CloudFront Function for viewer-request association."
  value       = aws_cloudfront_function.url_rewrite.arn
}

output "function_name" {
  description = "Name of the deployed CloudFront Function."
  value       = aws_cloudfront_function.url_rewrite.name
}
