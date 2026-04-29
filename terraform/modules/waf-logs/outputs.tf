###############################################################################
# WAF logs module — outputs.
#
# These are surfaced through the root module so:
#   - the WAF module can attach the Firehose ARN to the web ACL logging
#     configuration (Day 33's `log_destination_arn` plumbing); and
#   - operators can consume the resource names in BI tooling (Grafana,
#     QuickSight) without re-deriving them from input variables.
###############################################################################

###############################################################################
# Firehose.
###############################################################################

output "firehose_delivery_stream_arn" {
  description = "ARN of the Firehose delivery stream — pass to the WAF module as `log_destination_arn`."
  value       = aws_kinesis_firehose_delivery_stream.waf_logs.arn
}

output "firehose_delivery_stream_name" {
  description = "Name of the Firehose delivery stream (always prefixed `aws-waf-logs-`)."
  value       = aws_kinesis_firehose_delivery_stream.waf_logs.name
}

output "firehose_role_arn" {
  description = "ARN of the IAM role assumed by Firehose for log delivery."
  value       = aws_iam_role.firehose.arn
}

output "firehose_log_group_name" {
  description = "CloudWatch log group that captures Firehose delivery errors."
  value       = aws_cloudwatch_log_group.firehose.name
}

###############################################################################
# S3.
###############################################################################

output "log_bucket_id" {
  description = "Name of the S3 bucket that stores Parquet WAF logs."
  value       = aws_s3_bucket.waf_logs.id
}

output "log_bucket_arn" {
  description = "ARN of the WAF-logs S3 bucket."
  value       = aws_s3_bucket.waf_logs.arn
}

output "log_bucket_partition_root" {
  description = "S3 URI of the partition root (i.e. where Firehose writes year=YYYY/...)."
  value       = "s3://${aws_s3_bucket.waf_logs.bucket}/waf-logs/"
}

###############################################################################
# KMS.
###############################################################################

output "kms_key_arn" {
  description = "ARN of the customer-managed KMS key used for log encryption."
  value       = aws_kms_key.waf_logs.arn
}

output "kms_key_alias" {
  description = "Alias of the customer-managed KMS key (alias/<prefix>-waf-logs)."
  value       = aws_kms_alias.waf_logs.name
}

###############################################################################
# Glue.
###############################################################################

output "glue_database_name" {
  description = "Glue catalog database holding the waf_logs table."
  value       = aws_glue_catalog_database.waf_logs.name
}

output "glue_table_name" {
  description = "Glue catalog table that Firehose writes Parquet rows into."
  value       = aws_glue_catalog_table.waf_logs.name
}

output "glue_crawler_name" {
  description = "Name of the daily Glue crawler that detects schema drift and back-fills missing partitions."
  value       = aws_glue_crawler.waf_logs.name
}

###############################################################################
# Athena.
###############################################################################

output "athena_workgroup" {
  description = "Athena workgroup configured for WAF-log analytics."
  value       = aws_athena_workgroup.waf_logs.name
}

output "athena_results_bucket" {
  description = "S3 bucket where Athena writes query result CSVs (7-day expiry)."
  value       = aws_s3_bucket.athena_results.id
}

output "athena_named_query_ids" {
  description = "IDs of the saved Athena queries provisioned by this module."
  value = {
    top_blocked_ips          = aws_athena_named_query.top_blocked_ips.id
    top_matched_rules        = aws_athena_named_query.top_matched_rules.id
    status_code_distribution = aws_athena_named_query.status_code_distribution.id
    requests_by_country      = aws_athena_named_query.requests_by_country.id
    captcha_pass_rate        = aws_athena_named_query.captcha_pass_rate.id
    uri_attack_distribution  = aws_athena_named_query.uri_attack_distribution.id
    anomalous_user_agents    = aws_athena_named_query.anomalous_user_agents.id
    rate_limit_hits_per_path = aws_athena_named_query.rate_limit_hits_per_path.id
  }
}
