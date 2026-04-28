# =============================================================================
# Lambda@Edge module - input variables
# =============================================================================

variable "name_prefix" {
  description = "Prefix applied to every Lambda function and IAM role name. Keep <= 32 chars to leave room for suffix."
  type        = string

  validation {
    condition     = length(var.name_prefix) > 0 && length(var.name_prefix) <= 32
    error_message = "name_prefix must be 1-32 chars (Lambda name limit is 64, leaves room for function suffix)."
  }
}

variable "log_retention_days" {
  description = "Retention in days for Lambda@Edge CloudWatch log groups. Note: edge logs land in EVERY region's log group; this only sets the primary."
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be one of the values supported by CloudWatch Logs."
  }
}

variable "tags" {
  description = "Tags applied to all created resources."
  type        = map(string)
  default     = {}
}
