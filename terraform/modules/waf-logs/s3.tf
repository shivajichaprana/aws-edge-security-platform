###############################################################################
# WAF logs — S3 bucket + KMS CMK + lifecycle policy.
#
# Day 35 (`feat(waf-logs)`).
#
# Storage strategy (cost vs. retention):
#
#     Standard (0-30 d)   - hot tier for live incident triage / dashboards
#     Standard-IA (30 d+) - cooler tier for last-quarter retros
#     Glacier IR (90 d+)  - low-cost tier for compliance / forensic replay
#     Expiry (365 d)      - hard delete to satisfy GDPR / DPDP retention
#
# Bucket-level controls — all of these are mandatory for any
# log-aggregation bucket:
#   - public-access block (4/4)
#   - SSE-KMS with our customer-managed key
#   - bucket-owner-enforced ACL (ACLs disabled, all access via policy)
#   - versioning ENABLED so a delete-object call cannot evict logs
#   - lifecycle expiry on noncurrent versions to bound cost
#   - access-logging to a separate log-of-logs bucket (operator-provided)
###############################################################################

###############################################################################
# Customer-managed KMS key for WAF log encryption.
#
# We use a CMK (rather than aws/s3) so we can:
#   - tightly scope which principals decrypt logs (analysts, Athena role)
#   - rotate keys on a schedule (annual rotation enabled)
#   - capture key-usage in CloudTrail with a clear key alias
###############################################################################

resource "aws_kms_key" "waf_logs" {
  provider                = aws.us_east_1
  description             = "Customer-managed KMS key for WAF log delivery (Firehose -> S3)."
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  is_enabled              = true

  policy = data.aws_iam_policy_document.kms_key_policy.json

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-waf-logs-key"
    Component = "waf-logs"
  })
}

resource "aws_kms_alias" "waf_logs" {
  provider      = aws.us_east_1
  name          = "alias/${var.name_prefix}-waf-logs"
  target_key_id = aws_kms_key.waf_logs.key_id
}

###############################################################################
# KMS key policy — root retains admin (required so we don't lock ourselves
# out), Firehose service may encrypt, named analyst principals may decrypt.
###############################################################################

data "aws_iam_policy_document" "kms_key_policy" {
  # Root admin — required for break-glass and Terraform plan/apply.
  statement {
    sid    = "EnableRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Firehose encrypt-via-S3.
  statement {
    sid    = "AllowFirehoseEncrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # CloudWatch Logs — for the Firehose error log group.
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }

  # Analyst principals — operator-supplied list of IAM ARNs that may decrypt
  # the logs from Athena / S3 Console / scripted exports.
  dynamic "statement" {
    for_each = length(var.analyst_principal_arns) > 0 ? [1] : []

    content {
      sid    = "AllowAnalystDecrypt"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = var.analyst_principal_arns
      }
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
      ]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values = [
          "s3.${data.aws_region.current.name}.amazonaws.com",
          "athena.${data.aws_region.current.name}.amazonaws.com",
        ]
      }
    }
  }
}

###############################################################################
# Primary S3 bucket — destination for Firehose-written Parquet.
###############################################################################

resource "random_id" "bucket_suffix" {
  byte_length = 4
  keepers = {
    name_prefix = var.name_prefix
  }
}

resource "aws_s3_bucket" "waf_logs" {
  provider = aws.us_east_1
  bucket   = "${var.name_prefix}-waf-logs-${random_id.bucket_suffix.hex}"

  # `force_destroy = false` is essential — never let `terraform destroy`
  # nuke a bucket with thousands of forensic log objects.
  force_destroy = false

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-waf-logs"
    Component = "waf-logs"
    DataClass = "audit-logs"
  })
}

# Disable ACLs entirely — all access is mediated by bucket / KMS / IAM policy.
resource "aws_s3_bucket_ownership_controls" "waf_logs" {
  provider = aws.us_east_1
  bucket   = aws_s3_bucket.waf_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Block all public access — defence-in-depth so nothing leaks if a downstream
# integration mis-applies an ACL or sets up Cross-Account configuration wrong.
resource "aws_s3_bucket_public_access_block" "waf_logs" {
  provider                = aws.us_east_1
  bucket                  = aws_s3_bucket.waf_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SSE-KMS at rest using the CMK above. `bucket_key_enabled = true` slashes
# the per-PUT KMS API call volume (and cost) by reusing data keys.
resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  provider = aws.us_east_1
  bucket   = aws_s3_bucket.waf_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.waf_logs.arn
    }
    bucket_key_enabled = true
  }
}

# Versioning — protects against accidental deletes / overwrites. Combined with
# the lifecycle expiry on noncurrent versions, cost stays bounded.
resource "aws_s3_bucket_versioning" "waf_logs" {
  provider = aws.us_east_1
  bucket   = aws_s3_bucket.waf_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Bucket policy — TLS-only (denies any HTTP request) and KMS-only PUTs (denies
# any unencrypted PutObject). Hardens against mis-configured clients.
data "aws_iam_policy_document" "bucket_policy" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    resources = [
      aws_s3_bucket.waf_logs.arn,
      "${aws_s3_bucket.waf_logs.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyUnencryptedPuts"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    resources = ["${aws_s3_bucket.waf_logs.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid     = "DenyWrongKMSKey"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    resources = ["${aws_s3_bucket.waf_logs.arn}/*"]
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.waf_logs.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "waf_logs" {
  provider = aws.us_east_1
  bucket   = aws_s3_bucket.waf_logs.id
  policy   = data.aws_iam_policy_document.bucket_policy.json

  # The public-access-block must apply BEFORE the bucket policy; otherwise
  # AWS may reject the policy if it could create a public path.
  depends_on = [aws_s3_bucket_public_access_block.waf_logs]
}

###############################################################################
# Lifecycle policy.
#
# Day 0–30:    Standard       (~$0.023/GB-mo)
# Day 30–90:   Standard-IA    (~$0.0125/GB-mo, 30 d minimum)
# Day 90–365:  Glacier IR     (~$0.004/GB-mo, 90 d minimum)
# Day 365:     Expire         (delete current version)
# Noncurrent:  Expire after 30 d (keeps undelete window short for cost)
###############################################################################

resource "aws_s3_bucket_lifecycle_configuration" "waf_logs" {
  provider = aws.us_east_1
  bucket   = aws_s3_bucket.waf_logs.id

  rule {
    id     = "tiered-retention-and-expiry"
    status = "Enabled"

    # Apply the rule to every object in the bucket — dynamic partitioning
    # writes to many prefixes, so a wildcard filter is correct here.
    filter {
      prefix = ""
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  # Delete the error-output partition (Firehose's failed-record dump) faster
  # — these are operational data, not audit data, and balloon during outages.
  rule {
    id     = "expire-firehose-error-output"
    status = "Enabled"

    filter {
      prefix = "waf-logs-errors/"
    }

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}
