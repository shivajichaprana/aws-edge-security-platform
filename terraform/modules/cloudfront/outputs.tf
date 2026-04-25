###############################################################################
# CloudFront module — outputs.
###############################################################################

output "distribution_id" {
  description = "CloudFront distribution ID — use for invalidations and log-subscription targets."
  value       = aws_cloudfront_distribution.this.id
}

output "distribution_arn" {
  description = "ARN of the CloudFront distribution."
  value       = aws_cloudfront_distribution.this.arn
}

output "domain_name" {
  description = "*.cloudfront.net domain to use as the CNAME target in DNS."
  value       = aws_cloudfront_distribution.this.domain_name
}

output "hosted_zone_id" {
  description = "CloudFront hosted-zone ID (constant Z2FDTNDATAQYW2) for Route 53 ALIAS records."
  value       = aws_cloudfront_distribution.this.hosted_zone_id
}

output "etag" {
  description = "ETag of the distribution config — useful for in-place updates from CI."
  value       = aws_cloudfront_distribution.this.etag
}
