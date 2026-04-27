###############################################################################
# Bot Control — AWS managed rule group for sophisticated bot detection.
#
# Day 33 deliverable. Bot Control is the costliest managed rule group AWS
# offers (priced per 1M requests inspected) and consumes ~50 WCU on top of
# the existing managed rules. To keep cost predictable we do TWO things:
#
#   1. Run Bot Control with a *scope_down* statement so it only inspects
#      `/api/*` requests — typically high-value paths where automated abuse
#      shows up (credential stuffing, scraping, inventory hoarding). Static
#      assets, marketing pages, and health checks are excluded entirely.
#
#   2. Use the TARGETED inspection level. Bot Control offers two:
#        - COMMON  : signature-based detection (~50 WCU). Catches obvious
#                    bots like curl, python-requests, and known scrapers.
#        - TARGETED: COMMON + ML/heuristic features (~50 WCU + 2x request
#                    cost). Detects sophisticated bots, browser automation
#                    frameworks (Selenium, Puppeteer), and headless Chrome.
#
#      We default to TARGETED because the protected `/api/*` surface is
#      where attacker effort is highest. Operators who need a cheaper
#      baseline can flip `bot_control_inspection_level = "COMMON"`.
#
# Bot Control labels every request it processes with one of:
#   - awswaf:managed:aws:bot-control:bot:category:<category>
#   - awswaf:managed:aws:bot-control:signal:<signal>
#   - awswaf:managed:aws:bot-control:bot:name:<name>
#
# This module's `bot_label_responses` rule group inspects those labels and
# routes specific bot categories to CAPTCHA or challenge instead of
# blocking outright — that lets legitimate-but-mislabeled traffic resolve
# the challenge and proceed, while still applying friction.
#
# References:
#   - Bot Control rule list: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html
#   - Pricing: https://aws.amazon.com/waf/pricing/ (Bot Control add-on)
#   - Targeted vs Common: see docs/bot-control-guide.md
###############################################################################

# -----------------------------------------------------------------------------
# Local config — kept in this file so all bot-control knobs live together.
# main.tf consumes these via `local.bot_control_*`.
# -----------------------------------------------------------------------------
locals {
  bot_control_enabled          = var.bot_control_enabled
  bot_control_inspection_level = var.bot_control_inspection_level
  bot_control_scope_down_path  = var.bot_control_scope_down_path

  # Sub-rules of the Bot Control managed group that we *count* rather than
  # block. These cover legitimate use cases (HTTP libraries used by mobile
  # SDKs, automation frameworks used internally) and we route them to the
  # custom `bot_label_responses` rule group below where they get CAPTCHA
  # instead of an outright block.
  bot_control_count_rules = [
    "CategoryHttpLibrary",        # python-requests, axios, etc — could be legit SDK use
    "CategoryMonitoring",         # uptime checkers, synthetics
    "CategorySearchEngine",       # Googlebot, Bingbot — SEO matters
    "SignalAutomatedBrowser",     # headless Chrome / Puppeteer — applied via CAPTCHA below
  ]
}

# -----------------------------------------------------------------------------
# IPSet — trusted bot egress IPs that bypass Bot Control entirely.
#
# Some legitimate automation (your own monitoring, partner integrations)
# must never be challenged. Operators add their CIDRs to
# `var.trusted_bot_ips` and the BotControl rule's scope_down clause excludes
# them via NOT statement.
#
# Empty by default. AWS treats an empty IPSet as never matching.
# -----------------------------------------------------------------------------
resource "aws_wafv2_ip_set" "trusted_bots" {
  count = local.bot_control_enabled ? 1 : 0

  name               = "${var.name_prefix}-trusted-bots-v4"
  description        = "IPv4 CIDRs allowed to bypass Bot Control inspection (own monitoring, partners)."
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = var.trusted_bot_ips

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-trusted-bots-v4"
    Component = "waf"
    Purpose   = "bot-control-bypass"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------------------------------------------------------
# Custom rule group: bot label responders.
#
# Each rule matches a Bot Control label that we previously *counted* (rather
# than blocked) and converts it into a CAPTCHA or challenge action. This
# two-stage approach is the recommended Bot Control pattern: first label,
# then act on labels in a downstream rule group so the response can be
# tuned per category without re-deploying the managed rule group.
#
# WCU breakdown:
#   - Each label_match_statement is 5 WCU.
#   - CAPTCHA/challenge actions add 0 WCU directly but trigger token
#     verification at the edge.
# Total ~25 WCU; capacity set to 100 for headroom.
# -----------------------------------------------------------------------------
resource "aws_wafv2_rule_group" "bot_label_responses" {
  count = local.bot_control_enabled ? 1 : 0

  name     = "${var.name_prefix}-bot-label-responses-rg"
  scope    = "CLOUDFRONT"
  capacity = 100

  # ---------------------------------------------------------------------------
  # Rule 1 — CAPTCHA on automated browsers.
  # Bot Control's TARGETED level adds the `signal:automated_browser` label
  # to requests from headless browsers / automation frameworks.
  # ---------------------------------------------------------------------------
  rule {
    name     = "CaptchaAutomatedBrowser"
    priority = 1

    action {
      captcha {
        custom_request_handling {
          insert_header {
            name  = "x-bot-control-action"
            value = "captcha-automated-browser"
          }
        }
      }
    }

    statement {
      label_match_statement {
        scope = "LABEL"
        key   = "awswaf:managed:aws:bot-control:signal:automated_browser"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-Bot-CaptchaAutomatedBrowser"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 2 — CAPTCHA on HTTP-library traffic.
  # Mobile apps and SDKs sometimes register here. CAPTCHA is appropriate for
  # interactive endpoints; for pure machine-to-machine APIs use a tighter
  # `trusted_bot_ips` bypass instead.
  # ---------------------------------------------------------------------------
  rule {
    name     = "CaptchaHttpLibrary"
    priority = 2

    action {
      captcha {}
    }

    statement {
      label_match_statement {
        scope = "LABEL"
        key   = "awswaf:managed:aws:bot-control:bot:category:http_library"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-Bot-CaptchaHttpLibrary"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 3 — Silent challenge on monitoring traffic.
  # Uptime monitors and synthetic agents are mostly benign but should still
  # carry a WAF token so abusive ones can be rate-limited. Challenge is
  # token-based and invisible to well-behaved clients that re-use cookies.
  # ---------------------------------------------------------------------------
  rule {
    name     = "ChallengeMonitoring"
    priority = 3

    action {
      challenge {
        custom_request_handling {
          insert_header {
            name  = "x-bot-control-action"
            value = "challenge-monitoring"
          }
        }
      }
    }

    statement {
      label_match_statement {
        scope = "LABEL"
        key   = "awswaf:managed:aws:bot-control:bot:category:monitoring"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-Bot-ChallengeMonitoring"
      sampled_requests_enabled   = true
    }
  }

  # ---------------------------------------------------------------------------
  # Rule 4 — Allow search-engine crawlers explicitly.
  # Googlebot, Bingbot, etc. carry the `category:search_engine` label. We
  # allow them with no friction so SEO is preserved; the explicit rule is
  # there to make the intent visible in CloudWatch metrics.
  # ---------------------------------------------------------------------------
  rule {
    name     = "AllowSearchEngines"
    priority = 4

    action {
      allow {}
    }

    statement {
      label_match_statement {
        scope = "LABEL"
        key   = "awswaf:managed:aws:bot-control:bot:category:search_engine"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.metric_name}-Bot-AllowSearchEngines"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.metric_name}-BotLabelResponses"
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-bot-label-responses-rg"
    Component = "waf"
    Purpose   = "bot-label-handler"
  })

  lifecycle {
    create_before_destroy = true
  }
}
