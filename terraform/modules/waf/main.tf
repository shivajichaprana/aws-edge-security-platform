###############################################################################
# WAFv2 web ACL — CLOUDFRONT scope.
#
# Day 31 (baseline):
#   - Common, KnownBadInputs, SQLi managed rule groups
# Day 32 (this commit):
#   - Linux, IpReputation, AnonymousIpList managed rule groups
# Future:
#   - Day 32 follow-up commit: rate-limit + custom rule groups + geo allow-list
#   - Day 33: Bot Control + CAPTCHA / challenge actions
#   - Day 35: Firehose logging configuration
#
# IMPORTANT: every resource in this module MUST be created in us-east-1.
# The root passes the aliased provider explicitly; the module re-declares the
# requirement so consumers get an immediate error if they forget.
#
# WCU budget — six managed rule groups consume roughly 1,375 WCU. The hard
# WAFv2 default ceiling is 1,500 WCU per web ACL, so we exclude noisy
# sub-rules (SizeRestrictions_BODY) where appropriate to keep headroom for
# the rate-limit + custom rule groups added later in Day 32 and Bot Control
# in Day 33 (which adds ~50 WCU on top).
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
  description = "Edge WAFv2 web ACL fronting CloudFront — managed-rule baseline + Linux/IP-reputation/anonymous-IP groups."
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
  # Rule 1 — AWSManagedRulesCommonRuleSet  (priority 10, ~700 WCU)
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
  # Rule 2 — AWSManagedRulesKnownBadInputsRuleSet  (priority 20, ~200 WCU)
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
  # Rule 3 — AWSManagedRulesSQLiRuleSet  (priority 30, ~200 WCU)
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

  # ---------------------------------------------------------------------------
  # Rule 4 — AWSManagedRulesLinuxRuleSet  (priority 40, ~200 WCU)
  # Local-file-inclusion and shell-injection patterns common against Linux
  # origins (`/etc/passwd`, `${jndi:`-style probes that slip past common
  # rules, `;rm -rf`, etc.). Targets request URI, body, and cookies.
  # ---------------------------------------------------------------------------
  rule {
    name     = "AWSManagedRulesLinuxRuleSet"
    priority = 40

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesLinuxRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-Linux"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 5 — AWSManagedRulesAmazonIpReputationList  (priority 50, ~25 WCU)
  # AWS-curated reputation list of IPs known for vulnerability scanning,
  # DDoS sources, and bots. Cheapest possible rule — always near the top of
  # the chain so we eject known-bad traffic before paying for deep inspection.
  # ---------------------------------------------------------------------------
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 50

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-IpReputation"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 6 — AWSManagedRulesAnonymousIpList  (priority 60, ~50 WCU)
  # Tor exit nodes, proxies, anonymising VPNs, hosting providers used as
  # exfiltration infrastructure. Some businesses legitimately use these — we
  # keep the action as the rule-group default (block) but production owners
  # are encouraged to override per-rule to COUNT and re-evaluate.
  # ---------------------------------------------------------------------------
  rule {
    name     = "AWSManagedRulesAnonymousIpList"
    priority = 60

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAnonymousIpList"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-AnonymousIp"
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
