###############################################################################
# WAF logs module — input variables.
#
# All inputs below are intentionally tuned for the edge-security-platform's
# default deployment shape: low-to-moderate traffic, 12-month retention,
# CMK-encrypted at rest. Operators with different requirements override the
# specific knob they care about.
###############################################################################

variable "name_prefix" {
  description = "Resource-name prefix shared across all module-managed resources (e.g. edge-security-prod)."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,40}$", var.name_prefix))
    error_message = "name_prefix must be 3-41 chars, lowercase, start with a letter, and contain only [a-z0-9-]."
  }
}

variable "tags" {
  description = "Tags applied to every resource created by this module (merged onto resource-specific tags)."
  type        = map(string)
  default     = {}
}

###############################################################################
# Firehose buffering & retention.
###############################################################################

variable "firehose_buffer_mb" {
  description = <<-EOT
    Firehose S3 destination buffer size in MiB. Firehose flushes when
    EITHER the size or the interval threshold trips. Larger buffers produce
    fewer, bigger Parquet files (better Athena scan economics) at the cost
    of a longer log-to-S3 latency.

    Range: 64-128 (AWS lower bound is 64 for Parquet conversion).
  EOT
  type        = number
  default     = 64

  validation {
    condition     = var.firehose_buffer_mb >= 64 && var.firehose_buffer_mb <= 128
    error_message = "firehose_buffer_mb must be between 64 and 128 (Parquet conversion lower bound)."
  }
}

variable "firehose_buffer_seconds" {
  description = <<-EOT
    Firehose buffer flush interval, in seconds. AWS allows 0-900; for
    near-real-time SOC dashboards 60s is a reasonable default. Increase
    to 300s if your traffic is bursty and you want better Parquet packing.
  EOT
  type        = number
  default     = 60

  validation {
    condition     = var.firehose_buffer_seconds >= 60 && var.firehose_buffer_seconds <= 900
    error_message = "firehose_buffer_seconds must be between 60 and 900."
  }
}

variable "firehose_log_retention_days" {
  description = "CloudWatch retention for the Firehose-error log group. Short by design — these logs are operational, not audit."
  type        = number
  default     = 14

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365], var.firehose_log_retention_days)
    error_message = "firehose_log_retention_days must be one of CloudWatch's allowed values (1,3,5,7,14,30,60,90,120,150,180,365)."
  }
}

###############################################################################
# Storage retention & lifecycle.
###############################################################################

variable "log_retention_days" {
  description = <<-EOT
    Total retention (in days) for WAF log Parquet files. Default 365 days
    aligns with most regulator (PCI-DSS, SOC 2) audit windows. After this
    many days, objects are permanently deleted via the lifecycle expiry rule.
  EOT
  type        = number
  default     = 365

  validation {
    condition     = var.log_retention_days >= 90 && var.log_retention_days <= 2555
    error_message = "log_retention_days must be between 90 (regulator minimum) and 2555 (~7 years, KMS deletion-window safe ceiling)."
  }
}

###############################################################################
# Access controls.
###############################################################################

variable "analyst_principal_arns" {
  description = <<-EOT
    IAM ARNs of users / roles permitted to decrypt WAF logs (via S3 or
    Athena). Empty by default — only the root account, Firehose, and
    CloudWatch Logs can touch the CMK. Add the SOC analyst role / Athena
    workgroup-execution role here once known.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.analyst_principal_arns :
      can(regex("^arn:aws[a-zA-Z-]*:iam::[0-9]{12}:(role|user|root)(/.+)?$", arn))
    ])
    error_message = "Every analyst_principal_arns entry must be a full IAM ARN (role/user/root)."
  }
}

###############################################################################
# Athena cost controls.
###############################################################################

variable "bytes_scanned_cutoff_bytes" {
  description = <<-EOT
    Per-query data-scan ceiling enforced by the Athena workgroup. Queries
    that try to scan more data than this are aborted before a runaway
    bill is generated. Default 10 GiB covers all the supplied saved
    queries with months of data; raise it for ad-hoc forensic deep-dives.
  EOT
  type        = number
  default     = 10737418240 # 10 GiB

  validation {
    condition     = var.bytes_scanned_cutoff_bytes >= 10485760 # 10 MiB minimum per AWS quota
    error_message = "bytes_scanned_cutoff_bytes must be at least 10485760 (10 MiB), the AWS workgroup minimum."
  }
}
