###############################################################################
# CloudFront distribution — fronts an existing ALB origin and (optionally)
# attaches a WAFv2 web ACL ARN.
#
# Day-31 baseline only. Subsequent days add Lambda@Edge associations
# (Day 34), a CloudFront Function for URL rewrite (Day 34), and a real-time
# log subscription to a Firehose stream (Day 35).
###############################################################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.50"
      configuration_aliases = [aws.us_east_1]
    }
  }
}

locals {
  origin_id = "${var.name_prefix}-alb-origin"
}

resource "aws_cloudfront_distribution" "this" {
  provider = aws.us_east_1

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${var.name_prefix} edge distribution (managed by aws-edge-security-platform)"
  default_root_object = "index.html"
  http_version        = "http2and3"
  price_class         = var.price_class
  aliases             = var.aliases
  web_acl_id          = var.web_acl_arn

  # ---------------------------------------------------------------------------
  # Origin — an existing internet-facing or internal ALB.
  # ALBs cannot be reached via OAC (which is S3-only); we therefore use a
  # custom_origin_config and rely on a custom header secret to prevent the ALB
  # from accepting traffic that didn't pass through CloudFront. The header
  # value is wired up in a future day from SecretsManager — for now we set a
  # static placeholder you should override via tfvars before applying.
  # ---------------------------------------------------------------------------
  origin {
    domain_name = var.alb_dns_name
    origin_id   = local.origin_id
    origin_path = var.alb_origin_path

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_keepalive_timeout = 5
      origin_read_timeout      = 30
    }

    custom_header {
      name  = "X-Origin-Verify"
      value = "REPLACE_WITH_SECRET" # rotated via SecretsManager on Day 32
    }
  }

  # ---------------------------------------------------------------------------
  # Default cache behavior — forward host header for ALB virtual-host routing,
  # disable caching of authenticated/varying requests, allow standard HTTPS
  # methods, and gzip-compress eligible responses.
  # ---------------------------------------------------------------------------
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.origin_id

    viewer_protocol_policy = "redirect-to-https"
    compress               = var.compress

    min_ttl     = var.min_ttl
    default_ttl = var.default_ttl
    max_ttl     = var.max_ttl

    forwarded_values {
      query_string = true

      headers = [
        "Host",
        "Origin",
        "Authorization",
        "CloudFront-Viewer-Country",
        "CloudFront-Forwarded-Proto",
      ]

      cookies {
        forward = "all"
      }
    }
  }

  # ---------------------------------------------------------------------------
  # Restrictions — geographic restriction (none by default; managed via WAF
  # geo-match rules on Day 32 instead, which is more flexible).
  # ---------------------------------------------------------------------------
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # ---------------------------------------------------------------------------
  # Custom error responses — keep the origin from leaking 5xx HTML by serving
  # a friendly static page from the cache. Path is rewritten by a CloudFront
  # Function in Day 34; for now a 5-second cache prevents thundering herds.
  # ---------------------------------------------------------------------------
  custom_error_response {
    error_code         = 502
    response_code      = 502
    response_page_path = "/errors/502.html"
    error_caching_min_ttl = 5
  }

  custom_error_response {
    error_code         = 503
    response_code      = 503
    response_page_path = "/errors/503.html"
    error_caching_min_ttl = 5
  }

  custom_error_response {
    error_code         = 504
    response_code      = 504
    response_page_path = "/errors/504.html"
    error_caching_min_ttl = 5
  }

  # ---------------------------------------------------------------------------
  # Viewer certificate — defaults to the CloudFront default (cloudfront.net).
  # Once Route 53 + ACM are wired up (out-of-scope for Day 31) this block will
  # be replaced with `acm_certificate_arn` + `ssl_support_method = "sni-only"`.
  # ---------------------------------------------------------------------------
  viewer_certificate {
    cloudfront_default_certificate = true
  }

  # ---------------------------------------------------------------------------
  # Standard logging — optional; Day 35 sets up real-time logs via Kinesis
  # Data Streams + Firehose, which is materially better for security analytics.
  # ---------------------------------------------------------------------------
  dynamic "logging_config" {
    for_each = var.log_bucket_domain_name == null ? [] : [1]
    content {
      bucket          = var.log_bucket_domain_name
      include_cookies = false
      prefix          = "cloudfront-standard-logs/${var.name_prefix}/"
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-cf"
    Component = "cloudfront"
  })

  # CloudFront updates take ~5 min to propagate. `wait_for_deployment = false`
  # avoids blocking subsequent terraform applies that don't touch CF; flip to
  # true in CI runs that need the distribution fully deployed before tests.
  wait_for_deployment = false
}
