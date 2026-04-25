###############################################################################
# WAFv2 module — outputs.
###############################################################################

output "web_acl_id" {
  description = "ID of the WAFv2 web ACL."
  value       = aws_wafv2_web_acl.this.id
}

output "web_acl_arn" {
  description = "ARN of the WAFv2 web ACL — pass to CloudFront's `web_acl_id` attribute."
  value       = aws_wafv2_web_acl.this.arn
}

output "web_acl_name" {
  description = "Name of the WAFv2 web ACL."
  value       = aws_wafv2_web_acl.this.name
}

output "web_acl_capacity" {
  description = "WCU consumed by the web ACL — useful for budgeting against the 1500 default ceiling."
  value       = aws_wafv2_web_acl.this.capacity
}
