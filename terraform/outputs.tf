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
