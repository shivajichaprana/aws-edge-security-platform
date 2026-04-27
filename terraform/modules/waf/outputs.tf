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

###############################################################################
# Day 33 outputs — Bot Control + logging.
###############################################################################

output "bot_control_enabled" {
  description = "Whether the BotControl managed rule and label responder are deployed."
  value       = local.bot_control_enabled
}

output "bot_label_responses_rule_group_arn" {
  description = "ARN of the custom rule group that converts Bot Control labels into CAPTCHA/challenge actions. null when Bot Control is disabled."
  value       = local.bot_control_enabled ? aws_wafv2_rule_group.bot_label_responses[0].arn : null
}

output "trusted_bots_ipset_arn" {
  description = "ARN of the IPSet containing trusted-bot CIDRs that bypass Bot Control. null when Bot Control is disabled."
  value       = local.bot_control_enabled ? aws_wafv2_ip_set.trusted_bots[0].arn : null
}

output "logging_configuration_id" {
  description = "ID of the WAF logging configuration. null when log_destination_arn is empty (Day 35 wires this up)."
  value = (
    length(var.log_destination_arn) > 0
    ? aws_wafv2_web_acl_logging_configuration.this[0].id
    : null
  )
}
