# =============================================================================
# Lambda@Edge module - outputs
#
# CloudFront associations need the *qualified* ARN (including the published
# version), not the unqualified function ARN. We expose both for flexibility.
# =============================================================================

output "security_headers_qualified_arn" {
  description = "Versioned ARN of the security-headers function for CloudFront viewer-response association."
  value       = aws_lambda_function.security_headers.qualified_arn
}

output "geo_router_qualified_arn" {
  description = "Versioned ARN of the geo-router function for CloudFront origin-request association."
  value       = aws_lambda_function.geo_router.qualified_arn
}

output "header_rewrite_qualified_arn" {
  description = "Versioned ARN of the header-rewrite function for CloudFront viewer-request association."
  value       = aws_lambda_function.header_rewrite.qualified_arn
}

output "execution_role_arn" {
  description = "ARN of the shared execution role used by all three edge functions."
  value       = aws_iam_role.edge.arn
}

output "function_names" {
  description = "Map of logical name to deployed function name."
  value = {
    security_headers = aws_lambda_function.security_headers.function_name
    geo_router       = aws_lambda_function.geo_router.function_name
    header_rewrite   = aws_lambda_function.header_rewrite.function_name
  }
}
