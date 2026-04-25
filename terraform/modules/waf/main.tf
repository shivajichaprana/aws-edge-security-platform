###############################################################################
# WAFv2 web ACL — CLOUDFRONT scope.
#
# This is the Day-31 baseline: 3 AWS managed rule groups in COUNT-then-BLOCK
# order. Subsequent days add Linux/IpRep/AnonIP groups (Day 32), per-IP and
# per-URI rate limits (Day 32), Bot Control (Day 33) and full-request logging
# to Firehose (Day 35).
#
# IMPORTANT: every resource in this module MUST be created in us-east-1.
# The root passes the aliased provider explicitly; the module re-declares the
# requirement so consumers get an immediate error if they forget.
###############################################################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.50"
      configuration_aliases = [aws]
    }
  }
}

resource "aws_wafv2_web_acl" "this" {
  name        = "${var.name_prefix}-web-acl"
  description = "Edge WAFv2 web ACL fronting CloudFront — managed-rule baseline."
  scope       = "CLOUDFRONT"

  default_action {
    dynamic "allow" {
      for_each = var.default_action == "allow" ? [1] : []
      content {}
    }
    dynamic "block" {
      for_each = var.default_action == "block" ? [1] : []
      content {}
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 1 — AWSManagedRulesCommonRuleSet
  # OWASP Top-10-style protections (XSS, common LFI, NoSQL, generic-RFI, size
  # constraints). Always run first because it catches the broadest class of
  # script-kiddie payloads at the lowest cost.
  # ---------------------------------------------------------------------------
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        # Body inspection of file uploads can false-positive heavily on legit
        # multipart traffic. We let the size-constraint rule do its job and
        # exclude the body-rule that triggers on large requests.
        rule_action_override {
          name = "SizeRestrictions_BODY"
          action_to_use {
            count {}
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-CommonRules"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 2 — AWSManagedRulesKnownBadInputsRuleSet
  # Catches exploits for log4shell, java deserialization, php-tags, etc.
  # ---------------------------------------------------------------------------
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-KnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 3 — AWSManagedRulesSQLiRuleSet
  # SQL-injection signatures across query string, body, and cookies.
  # Higher priority number = evaluated later, so this runs after the cheaper
  # generic rules above to keep cost predictable.
  # ---------------------------------------------------------------------------
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-SQLi"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = var.metric_name
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-web-acl"
    Component = "waf"
  })

  # Web ACLs are referenced by CloudFront distributions; replacing one in place
  # would briefly leave CloudFront pointing at a deleted ACL. Force
  # create-before-destroy so the new ACL exists before the distribution is
  # re-associated.
  lifecycle {
    create_before_destroy = true
  }
}
