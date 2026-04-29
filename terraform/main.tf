###############################################################################
# Root composition for the aws-edge-security-platform stack.
#
# Modules wired up to date:
#   - waf:        AWSManagedRulesCommonRuleSet + KnownBadInputs + SQLi +
#                 Linux + IpReputation + AnonymousIpList + rate-limit +
#                 custom rules + Bot Control + logging configuration.
#   - cloudfront: distribution with the upstream ALB as origin and the WAF
#                 web ACL ARN attached.
#   - lambda-edge: security-headers, geo-router, header-rewrite functions
#                 and a CloudFront URL-rewrite function (Day 34).
#   - waf-logs:   Firehose -> S3 (Parquet) pipeline + Glue catalog + Athena
#                 saved queries (Day 35). Wired BACK into the WAF module so
#                 the web ACL logging configuration points at our Firehose.
#
# All us-east-1-only resources (CloudFront, WAF CLOUDFRONT scope, Lambda@Edge,
# WAF logging Firehose) consume the aliased provider `aws.us_east_1`.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  # The fully qualified resource-name prefix used throughout the stack.
  name_prefix = "${var.project_name}-${var.environment}"

  default_tags = merge({
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Repository  = "aws-edge-security-platform"
    Owner       = "platform-security"
  }, var.extra_tags)
}

###############################################################################
# WAF logs — Firehose / S3 / Glue / Athena.
#
# Provisioned BEFORE the WAF module (and passed in via log_destination_arn)
# so the web-ACL logging configuration can attach on the very first apply.
###############################################################################
module "waf_logs" {
  source = "./modules/waf-logs"
  count  = var.enable_waf && var.enable_waf_logs ? 1 : 0

  providers = {
    aws.us_east_1 = aws.us_east_1
  }

  name_prefix             = local.name_prefix
  log_retention_days      = var.waf_log_retention_days
  analyst_principal_arns  = var.waf_logs_analyst_principal_arns
  tags                    = local.default_tags
}

###############################################################################
# WAFv2 web ACL (CLOUDFRONT scope).
#
# `count` lets operators temporarily disable WAF (e.g. during DDoS mitigation
# bypass) without ripping it out of state. The CloudFront module accepts a
# nullable WAF ARN for the same reason.
###############################################################################
module "waf" {
  source = "./modules/waf"
  count  = var.enable_waf ? 1 : 0

  providers = {
    aws = aws.us_east_1
  }

  name_prefix         = local.name_prefix
  log_destination_arn = var.enable_waf_logs ? module.waf_logs[0].firehose_delivery_stream_arn : ""
  tags                = local.default_tags
}

###############################################################################
# CloudFront distribution.
#
# CloudFront resources live in us-east-1 only; we pass the aliased provider
# explicitly to avoid any ambiguity if the root provider changes region.
###############################################################################
module "cloudfront" {
  source = "./modules/cloudfront"

  providers = {
    aws.us_east_1 = aws.us_east_1
  }

  name_prefix     = local.name_prefix
  alb_dns_name    = var.alb_dns_name
  alb_origin_path = var.alb_origin_path
  price_class     = var.price_class
  web_acl_arn     = var.enable_waf ? module.waf[0].web_acl_arn : null
  aliases         = [var.root_domain, "www.${var.root_domain}"]
  tags            = local.default_tags
}
