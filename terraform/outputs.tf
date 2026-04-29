###############################################################################
# Root outputs - surface the bits other systems most often need to consume.
###############################################################################

output "cloudfront_distribution_id" {
  description = "ID of the CloudFront distribution. Used for invalidations and log subscriptions."
  value       = module.cloudfront.distribution_id
}

output "cloudfront_domain_name" {
  description = "The .cloudfront.net domain name of the distribution. Point your apex/CNAME here."
  value       = module.cloudfront.domain_name
}

output "cloudfront_arn" {
  description = "ARN of the CloudFront distribution."
  value       = module.cloudfront.distribution_arn
}

output "waf_web_acl_arn" {
  description = "ARN of the WAFv2 web ACL associated with CloudFront (null if WAF disabled)."
  value       = var.enable_waf ? module.waf[0].web_acl_arn : null
}

output "waf_web_acl_id" {
  description = "ID of the WAFv2 web ACL (null if WAF disabled)."
  value       = var.enable_waf ? module.waf[0].web_acl_id : null
}

###############################################################################
# Day 35 — WAF logs (Firehose / Glue / Athena).
###############################################################################

output "waf_logs_firehose_arn" {
  description = "ARN of the Firehose delivery stream that ships WAF logs to S3 (null when waf logs disabled)."
  value       = var.enable_waf && var.enable_waf_logs ? module.waf_logs[0].firehose_delivery_stream_arn : null
}

output "waf_logs_bucket" {
  description = "S3 bucket holding partitioned Parquet WAF logs (null when waf logs disabled)."
  value       = var.enable_waf && var.enable_waf_logs ? module.waf_logs[0].log_bucket_id : null
}

output "waf_logs_glue_database" {
  description = "Glue database name with the waf_logs table (null when waf logs disabled)."
  value       = var.enable_waf && var.enable_waf_logs ? module.waf_logs[0].glue_database_name : null
}

output "waf_logs_athena_workgroup" {
  description = "Athena workgroup configured for WAF analytics (null when waf logs disabled)."
  value       = var.enable_waf && var.enable_waf_logs ? module.waf_logs[0].athena_workgroup : null
}
