###############################################################################
# Root composition for the aws-edge-security-platform stack.
#
# At the Day-31 baseline this wires together two modules:
#   - waf:        AWSManagedRulesCommonRuleSet + KnownBadInputs + SQLi.
#   - cloudfront: distribution with the upstream ALB as origin and the WAF web
#                 ACL ARN attached.
#
# Both modules live alongside this file under ./modules and are versioned with
# the rest of the repo. Future days extend the WAF module with rate limits,
# bot control, and logging; and add lambda-edge / waf-logs modules.
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

  name_prefix = local.name_prefix
  tags        = local.default_tags
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

  name_prefix       = local.name_prefix
  alb_dns_name      = var.alb_dns_name
  alb_origin_path   = var.alb_origin_path
  price_class       = var.price_class
  web_acl_arn       = var.enable_waf ? module.waf[0].web_acl_arn : null
  aliases           = [var.root_domain, "www.${var.root_domain}"]
  tags              = local.default_tags
}
