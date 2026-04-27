###############################################################################
# WAFv2 module — input variables.
###############################################################################

variable "name_prefix" {
  description = "Resource-name prefix (e.g. edge-security-dev). Web ACL is named ${name_prefix}-web-acl."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,40}$", var.name_prefix))
    error_message = "name_prefix must be 3-41 chars, lowercase, start with a letter, and contain only [a-z0-9-]."
  }
}

variable "default_action" {
  description = "Default action when no rule matches. 'allow' lets traffic through; 'block' is fail-closed."
  type        = string
  default     = "allow"

  validation {
    condition     = contains(["allow", "block"], var.default_action)
    error_message = "default_action must be 'allow' or 'block'."
  }
}

variable "metric_name" {
  description = "CloudWatch metric name suffix used for visibility on the web ACL."
  type        = string
  default     = "edgeWebAcl"
}

variable "tags" {
  description = "Tags applied to every WAF resource created by this module."
  type        = map(string)
  default     = {}
}

###############################################################################
# Day 32 — geo allow-list, blocked-IP list, rate-limit thresholds.
###############################################################################

variable "allowed_countries" {
  description = <<-EOT
    Optional ISO 3166-1 alpha-2 country code allow-list. When non-empty, the
    GeoAllowList rule (priority 90) blocks every request whose
    `CloudFront-Viewer-Country` does not appear in this list. Pass `[]`
    (default) to disable geo-fencing entirely.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for c in var.allowed_countries : can(regex("^[A-Z]{2}$", c))
    ])
    error_message = "Every country code must be an uppercase ISO 3166-1 alpha-2 string (e.g. US, GB, IN)."
  }
}

variable "blocked_ips" {
  description = <<-EOT
    CIDR ranges that should be unconditionally blocked at the edge. Both IPv4
    and IPv6 are supported; the module partitions the input by family and
    creates one IPSet per family, then references both in the BlockListedIPs
    rule of the custom rule group. Empty list keeps the rule wired up but
    means it never matches.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.blocked_ips :
      can(cidrnetmask(cidr)) || can(cidrhost(cidr, 0))
    ])
    error_message = "Every entry of blocked_ips must be a valid IPv4 or IPv6 CIDR."
  }
}

variable "global_rate_limit" {
  description = <<-EOT
    Per-IP request limit, measured over a 5-minute sliding window, that
    triggers the global rate-limit rule. AWS minimum is 100; AWS maximum is
    20,000,000. Default 2,000 covers typical SaaS traffic per individual user
    while still catching scrapers.
  EOT
  type        = number
  default     = 2000

  validation {
    condition     = var.global_rate_limit >= 100 && var.global_rate_limit <= 20000000
    error_message = "global_rate_limit must be between 100 and 20,000,000 requests per 5 minutes (AWS WAF limits)."
  }
}

variable "login_rate_limit" {
  description = <<-EOT
    Per-IP request limit, over 5 minutes, applied only to the path defined by
    `login_path`. Tighter than global because credential-stuffing tools fire
    thousands of attempts; AWS WAF enforces a 100/5min minimum on rate-based
    rules so that is the floor we use.
  EOT
  type        = number
  default     = 100

  validation {
    condition     = var.login_rate_limit >= 100 && var.login_rate_limit <= 20000000
    error_message = "login_rate_limit must be between 100 and 20,000,000 (AWS WAF rate-based rule minimum is 100)."
  }
}

variable "login_path" {
  description = "URL path prefix used by the login rate-limit scope-down statement."
  type        = string
  default     = "/login"

  validation {
    condition     = can(regex("^/", var.login_path))
    error_message = "login_path must start with a forward slash."
  }
}

variable "rate_limit_action" {
  description = "Action for rate-limit hits. 'block' for production; 'count' to observe before enforcing."
  type        = string
  default     = "block"

  validation {
    condition     = contains(["block", "count"], var.rate_limit_action)
    error_message = "rate_limit_action must be 'block' or 'count'."
  }
}

###############################################################################
# Day 33 — Bot Control + CAPTCHA / challenge actions + WAF logging.
###############################################################################

variable "bot_control_enabled" {
  description = <<-EOT
    Master switch for the AWSManagedRulesBotControlRuleSet and the
    accompanying `bot_label_responses` custom rule group. Disable in
    pre-production or when running cost-sensitive workloads — Bot Control
    has request-based pricing in addition to the standard WAF charges.
  EOT
  type        = bool
  default     = true
}

variable "bot_control_inspection_level" {
  description = <<-EOT
    Bot Control inspection level. COMMON is signature-based (cheaper);
    TARGETED adds ML / behavioural heuristics (catches sophisticated bots
    such as headless Chrome, Selenium, Puppeteer). See
    docs/bot-control-guide.md for the trade-off.
  EOT
  type        = string
  default     = "TARGETED"

  validation {
    condition     = contains(["COMMON", "TARGETED"], var.bot_control_inspection_level)
    error_message = "bot_control_inspection_level must be 'COMMON' or 'TARGETED'."
  }
}

variable "bot_control_scope_down_path" {
  description = <<-EOT
    URI path prefix that constrains Bot Control to only inspect a subset
    of requests. Defaults to `/api` so we skip cheap static traffic and
    avoid Bot Control's per-request fee on assets. Pass `/` to inspect
    every request.
  EOT
  type        = string
  default     = "/api"

  validation {
    condition     = can(regex("^/", var.bot_control_scope_down_path))
    error_message = "bot_control_scope_down_path must start with a forward slash."
  }
}

variable "trusted_bot_ips" {
  description = <<-EOT
    IPv4 CIDRs allowed to bypass Bot Control inspection (typically your
    own monitoring egress and partner integrations). Empty by default;
    AWS treats an empty IPSet as never-matching so the bypass is a no-op.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.trusted_bot_ips : can(cidrnetmask(cidr))
    ])
    error_message = "Every trusted_bot_ips entry must be a valid IPv4 CIDR (e.g. 10.0.0.0/16)."
  }
}

variable "captcha_paths" {
  description = <<-EOT
    URI path prefixes that trigger a CAPTCHA challenge instead of a
    block. Default covers the canonical authentication surfaces where
    CAPTCHA is more user-friendly than a hard block. Set to `[]` to
    disable.
  EOT
  type        = list(string)
  default     = ["/login", "/signup"]

  validation {
    condition = alltrue([
      for p in var.captcha_paths : can(regex("^/", p))
    ])
    error_message = "Every captcha_paths entry must start with a forward slash."
  }
}

variable "challenge_paths" {
  description = <<-EOT
    URI path prefixes that trigger a silent token challenge. Useful on
    high-value transactional endpoints (`/checkout`) where blocking real
    customers is unacceptable but unauthenticated bots must be filtered
    out. Set to `[]` to disable.
  EOT
  type        = list(string)
  default     = ["/checkout"]

  validation {
    condition = alltrue([
      for p in var.challenge_paths : can(regex("^/", p))
    ])
    error_message = "Every challenge_paths entry must start with a forward slash."
  }
}

variable "log_destination_arn" {
  description = <<-EOT
    ARN of a Kinesis Firehose delivery stream that receives WAF logs.
    Created in Day 35 (`feat(waf-logs)`). Pass `""` to disable logging
    entirely (the logging configuration resource is omitted via count).
  EOT
  type        = string
  default     = ""

  validation {
    condition = (
      var.log_destination_arn == "" ||
      can(regex("^arn:aws[a-zA-Z-]*:firehose:[a-z0-9-]+:[0-9]{12}:deliverystream/.+$", var.log_destination_arn))
    )
    error_message = "log_destination_arn must be empty or a valid Firehose delivery-stream ARN."
  }
}
