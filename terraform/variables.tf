###############################################################################
# Root variables.
###############################################################################

variable "project_name" {
  description = "Short identifier prefixed onto every resource name (e.g. edge-security)."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,32}$", var.project_name))
    error_message = "project_name must be 3-33 chars, lowercase, start with a letter, and contain only [a-z0-9-]."
  }
}

variable "environment" {
  description = "Deployment environment. Used in tagging and resource names."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  description = "Primary AWS region for non-edge regional resources (S3, Firehose, Athena, Glue)."
  type        = string
  default     = "ap-south-1"
}

variable "root_domain" {
  description = "Apex domain served by CloudFront (e.g. example.com)."
  type        = string
}

variable "alb_dns_name" {
  description = "DNS name of the upstream Application Load Balancer that CloudFront will use as origin."
  type        = string
}

variable "alb_origin_path" {
  description = "Optional path prefix on the ALB origin (set to empty string for root)."
  type        = string
  default     = ""
}

variable "price_class" {
  description = "CloudFront price class. PriceClass_100 = NA+EU only (cheapest); All = global."
  type        = string
  default     = "PriceClass_100"

  validation {
    condition     = contains(["PriceClass_100", "PriceClass_200", "PriceClass_All"], var.price_class)
    error_message = "price_class must be one of: PriceClass_100, PriceClass_200, PriceClass_All."
  }
}

variable "enable_waf" {
  description = "Whether to provision the WAFv2 web ACL and associate it with CloudFront."
  type        = bool
  default     = true
}

variable "extra_tags" {
  description = "Additional resource tags merged on top of project defaults."
  type        = map(string)
  default     = {}
}
