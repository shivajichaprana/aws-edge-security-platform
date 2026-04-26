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
