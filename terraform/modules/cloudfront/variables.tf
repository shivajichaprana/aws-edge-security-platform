###############################################################################
# CloudFront module — input variables.
###############################################################################

variable "name_prefix" {
  description = "Resource-name prefix; the distribution's caller_reference and tags are derived from this."
  type        = string
}

variable "alb_dns_name" {
  description = "DNS name of the ALB origin (e.g. internal-alb-1234.elb.amazonaws.com)."
  type        = string

  validation {
    condition     = length(var.alb_dns_name) > 0
    error_message = "alb_dns_name cannot be empty — point this at the ALB CloudFront should front."
  }
}

variable "alb_origin_path" {
  description = "Optional path on the ALB origin (default: empty for root)."
  type        = string
  default     = ""
}

variable "aliases" {
  description = "List of CNAMEs (alternate domain names) to attach to the distribution."
  type        = list(string)
  default     = []
}

variable "price_class" {
  description = "CloudFront price class — controls which edge locations are used."
  type        = string
  default     = "PriceClass_100"

  validation {
    condition     = contains(["PriceClass_100", "PriceClass_200", "PriceClass_All"], var.price_class)
    error_message = "price_class must be PriceClass_100, PriceClass_200, or PriceClass_All."
  }
}

variable "web_acl_arn" {
  description = "ARN of a WAFv2 web ACL (CLOUDFRONT scope) to attach. Pass null to skip association."
  type        = string
  default     = null
}

variable "compress" {
  description = "Whether CloudFront should gzip/brotli-compress eligible responses."
  type        = bool
  default     = true
}

variable "default_ttl" {
  description = "Default TTL (seconds) for objects without explicit Cache-Control."
  type        = number
  default     = 86400 # 1 day
}

variable "min_ttl" {
  description = "Minimum TTL (seconds) — sets the floor regardless of origin headers."
  type        = number
  default     = 0
}

variable "max_ttl" {
  description = "Maximum TTL (seconds) — caps the cache lifetime."
  type        = number
  default     = 31536000 # 1 year
}

variable "log_bucket_domain_name" {
  description = "Optional S3 bucket DOMAIN NAME (e.g. my-bucket.s3.amazonaws.com) for CloudFront standard logs. Null disables standard logging — Day 35 wires up real-time WAF logs separately."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to the distribution."
  type        = map(string)
  default     = {}
}
