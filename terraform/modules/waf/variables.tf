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
