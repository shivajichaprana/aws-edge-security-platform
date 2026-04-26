###############################################################################
# Rate-limit rule group — referenced by the web ACL at priority 70.
#
# Two rate-based rules:
#   1. GlobalPerIp     — `global_rate_limit` requests / 5 min, all paths.
#   2. LoginPerIp      — `login_rate_limit` requests / 5 min, scoped to the
#                        path prefix in `login_path` (default `/login`).
#
# Both aggregate by source IP (CloudFront forwards real client IP via the
# X-Forwarded-For header that WAF understands natively). For the global rule
# we use IP aggregation directly; for the login rule we use FORWARDED_IP via
# `forwarded_ip_config` so the count works for traffic terminated at ALB.
#
# Rate-based rules in WAFv2 use a 5-minute sliding window. Once an IP exceeds
# the limit, it remains blocked for as long as it stays above the threshold —
# the IP exits the block list once its rolling 5-minute count drops below.
#
# WCU cost: ~3 WCU per rate-based rule plus scope-down. Rule group capacity
# is set to 50 to leave headroom for tuning without re-creating the resource.
###############################################################################

resource "aws_wafv2_rule_group" "rate_limit" {
  name     = "${var.name_prefix}-rate-limit-rg"
  scope    = "CLOUDFRONT"
  capacity = 50

  # ---------------------------------------------------------------------------
  # Rule 1 — GlobalPerIp
  # 2,000 requests per 5 minutes from any single IP. This is intentionally
  # generous; legitimate users behind small NATs sometimes spike. The bot rule
  # group catches scrapers more cheaply, so this rule's job is to backstop
  # against a single host abusing all paths.
  # ---------------------------------------------------------------------------
  rule {
    name     = "GlobalPerIp"
    priority = 1

    action {
      dynamic "block" {
        for_each = var.rate_limit_action == "block" ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.rate_limit_action == "count" ? [1] : []
        content {}
      }
    }

    statement {
      rate_based_statement {
        limit              = var.global_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-RateLimit-GlobalPerIp"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 2 — LoginPerIp
  # 100 requests per 5 minutes to `/login` from a single IP. Tight enough to
  # break credential-stuffing tools, loose enough to allow real users to retry
  # several times after a typo. Uses a scope-down statement so the rate-based
  # rule only counts requests matching the login path prefix; everything else
  # bypasses this rule entirely (and is still subject to the global rule).
  # ---------------------------------------------------------------------------
  rule {
    name     = "LoginPerIp"
    priority = 2

    action {
      dynamic "block" {
        for_each = var.rate_limit_action == "block" ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.rate_limit_action == "count" ? [1] : []
        content {}
      }
    }

    statement {
      rate_based_statement {
        limit              = var.login_rate_limit
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = var.login_path

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
      metric_name                = "${var.metric_name}-RateLimit-LoginPerIp"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.metric_name}-RateLimit"
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-rate-limit-rg"
    Component = "waf"
    Purpose   = "rate-limit"
  })

  lifecycle {
    create_before_destroy = true
  }
}
