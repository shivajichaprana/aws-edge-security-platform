###############################################################################
# Custom block rules — referenced by the web ACL at priority 80.
#
# Three rules wrapped in a single rule group:
#   1. BlockListedIPs       — block any source IP listed in `blocked_ips`.
#   2. BlockMissingUA       — block requests with no `User-Agent` header.
#   3. BlockPathTraversal   — block obvious traversal patterns (`..`, `%2e%2e`)
#                             in the URI path.
#
# Each rule is independently auditable in CloudWatch via its own metric name.
# The rule group is built unconditionally; the BlockListedIPs rule short-
# circuits when the IP set is empty thanks to AWS's behaviour of not matching
# an empty IPSet.
#
# WCU cost: ~5 WCU IPSetRef + 4 WCU header inspection + 6 WCU URI inspection
# = roughly 15 WCU. Capacity is set to 50 for headroom.
###############################################################################

# -----------------------------------------------------------------------------
# IP set holding the blocklisted CIDRs.
#
# WAFv2 only allows a *single address family* per IPSet, so we partition
# `var.blocked_ips` into IPv4 and IPv6 buckets and create one set for each.
# The custom rule group references both with an OR statement.
# -----------------------------------------------------------------------------
locals {
  blocked_ipv4 = [
    for cidr in var.blocked_ips : cidr if !strcontains(cidr, ":")
  ]
  blocked_ipv6 = [
    for cidr in var.blocked_ips : cidr if strcontains(cidr, ":")
  ]
}

resource "aws_wafv2_ip_set" "blocked_v4" {
  name               = "${var.name_prefix}-blocked-v4"
  description        = "IPv4 CIDRs unconditionally blocked by the custom rule group."
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  # WAFv2 IPSets must always have at least one entry conceptually, but Terraform
  # supports an empty list — AWS treats an empty IPSet as never matching, so we
  # can safely use this as a "kill switch" enabled by simply adding entries.
  addresses = local.blocked_ipv4

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-blocked-v4"
    Component = "waf"
    Family    = "ipv4"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_wafv2_ip_set" "blocked_v6" {
  name               = "${var.name_prefix}-blocked-v6"
  description        = "IPv6 CIDRs unconditionally blocked by the custom rule group."
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV6"
  addresses          = local.blocked_ipv6

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-blocked-v6"
    Component = "waf"
    Family    = "ipv6"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------------------------------------------------------
# Custom rule group: 3 hand-authored rules.
# -----------------------------------------------------------------------------
resource "aws_wafv2_rule_group" "custom_rules" {
  name     = "${var.name_prefix}-custom-rg"
  scope    = "CLOUDFRONT"
  capacity = 50

  # ---------------------------------------------------------------------------
  # Rule 1 — BlockListedIPs
  # IPSetReferenceStatement with an OR over IPv4 and IPv6 sets. Cheap, runs
  # first inside the rule group so we never pay for downstream inspection
  # against known-bad sources.
  # ---------------------------------------------------------------------------
  rule {
    name     = "BlockListedIPs"
    priority = 1

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.blocked_v4.arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.blocked_v6.arn
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-Custom-BlockListedIPs"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 2 — BlockMissingUA
  # Real browsers and almost every legitimate API client send a User-Agent
  # header. Requests without one are overwhelmingly automated scanners. The
  # SizeConstraint of "absent or empty" is implemented as size < 1 with no
  # transformations, applied to the UA header.
  # ---------------------------------------------------------------------------
  rule {
    name     = "BlockMissingUA"
    priority = 2

    action {
      block {}
    }

    statement {
      size_constraint_statement {
        comparison_operator = "LT"
        size                = 1

        field_to_match {
          single_header {
            name = "user-agent"
          }
        }

        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-Custom-BlockMissingUA"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 3 — BlockPathTraversal
  # Blocks the most common URL-encoded and raw forms of `..` traversal in the
  # URI path. Three OR'd byte-match statements with two transformations each
  # (URL-decode then lowercase) to defeat trivial encoding tricks.
  # ---------------------------------------------------------------------------
  rule {
    name     = "BlockPathTraversal"
    priority = 3

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "../"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "..\\"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          byte_match_statement {
            positional_constraint = "CONTAINS"
            search_string         = "%2e%2e"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-Custom-BlockPathTraversal"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.metric_name}-CustomRules"
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-custom-rg"
    Component = "waf"
    Purpose   = "custom-block"
  })

  lifecycle {
    create_before_destroy = true
  }
}
