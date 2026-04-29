###############################################################################
# WAF logs — Kinesis Data Firehose delivery stream.
#
# Day 35 (`feat(waf-logs)`).
#
# Pipeline shape:
#
#   WAFv2 web ACL (us-east-1, CLOUDFRONT scope)
#       |  aws_wafv2_web_acl_logging_configuration  (Day 33, in waf module)
#       v
#   Kinesis Firehose delivery stream  <-- THIS RESOURCE
#       |  - dynamic partitioning by date (year/month/day/hour)
#       |  - record format conversion: JSON -> Parquet via Glue catalog
#       |  - server-side encryption with the customer-managed KMS key
#       v
#   S3 bucket (private, KMS-encrypted, lifecycled — see s3.tf)
#       |  s3://<bucket>/waf-logs/year=YYYY/month=MM/day=DD/hour=HH/
#       v
#   Glue catalog + Athena (queries from athena.tf)
#
# IMPORTANT — region considerations:
#   - The web ACL is in us-east-1 (CLOUDFRONT scope). WAF logging requires
#     the destination Firehose to be in the SAME region as the web ACL.
#   - Therefore this Firehose, its KMS key, IAM role, and S3 bucket are all
#     in us-east-1. The aliased provider `aws.us_east_1` is wired through
#     the module via `configuration_aliases`.
#
#   - WAF requires the Firehose name to start with `aws-waf-logs-`. This
#     prefix is enforced by the aws_wafv2_web_acl_logging_configuration
#     API, not by Firehose itself, but we bake it in so callers can't
#     accidentally violate it.
#
# References:
#   - Firehose delivery stream resource:
#     https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kinesis_firehose_delivery_stream
#   - WAF logging requirements:
#     https://docs.aws.amazon.com/waf/latest/developerguide/logging-kinesis.html
#   - Dynamic partitioning:
#     https://docs.aws.amazon.com/firehose/latest/dev/dynamic-partitioning.html
###############################################################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.50"
      configuration_aliases = [aws.us_east_1]
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

###############################################################################
# Data sources for the us-east-1 account context.
#
# We need the partition + region + account_id strings inside ARNs and IAM
# policy documents below. Pulling them from data sources (rather than
# hard-coding) lets the module work in GovCloud or China partitions without
# code changes.
###############################################################################

data "aws_caller_identity" "current" {
  provider = aws.us_east_1
}

data "aws_partition" "current" {
  provider = aws.us_east_1
}

data "aws_region" "current" {
  provider = aws.us_east_1
}

###############################################################################
# Random suffix.
#
# Firehose delivery-stream names are GLOBALLY unique within an account+region
# (deletion is eventually consistent), so we tack a 6-char hex suffix onto the
# user-supplied prefix to avoid replace-after-destroy collisions when the
# stack churns.
###############################################################################

resource "random_id" "firehose_suffix" {
  byte_length = 3
  keepers = {
    name_prefix = var.name_prefix
  }
}

locals {
  # WAF mandates the `aws-waf-logs-` prefix on the delivery stream name.
  firehose_name = "aws-waf-logs-${var.name_prefix}-${random_id.firehose_suffix.hex}"

  # Partition-aware base ARN segments used in IAM policy documents.
  s3_bucket_arn = aws_s3_bucket.waf_logs.arn
  kms_key_arn   = aws_kms_key.waf_logs.arn

  # Dynamic-partitioning prefix expressions. Firehose injects the namespace
  # values from `metadata_extraction` into the S3 key per record.
  s3_prefix       = "waf-logs/year=!{partitionKeyFromQuery:year}/month=!{partitionKeyFromQuery:month}/day=!{partitionKeyFromQuery:day}/hour=!{partitionKeyFromQuery:hour}/"
  s3_error_prefix = "waf-logs-errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/"
}

###############################################################################
# CloudWatch log group for Firehose error logging.
#
# Firehose writes its own delivery errors (S3 PutObject failures, format
# conversion exceptions, etc.) to a CloudWatch log group. We provision a
# dedicated group with a short retention so a stuck delivery doesn't silently
# bleed money and is easy to discover.
###############################################################################

resource "aws_cloudwatch_log_group" "firehose" {
  provider          = aws.us_east_1
  name              = "/aws/kinesisfirehose/${local.firehose_name}"
  retention_in_days = var.firehose_log_retention_days
  kms_key_id        = aws_kms_key.waf_logs.arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-firehose-logs"
    Component = "waf-logs"
  })
}

resource "aws_cloudwatch_log_stream" "firehose_s3_delivery" {
  provider       = aws.us_east_1
  name           = "S3Delivery"
  log_group_name = aws_cloudwatch_log_group.firehose.name
}

###############################################################################
# Firehose IAM role.
#
# Trust policy: only the regional firehose service principal may assume it.
# Permissions: write to our log bucket, encrypt/decrypt with the WAF KMS key,
# call the Glue catalog for Parquet schema, and emit error logs to CloudWatch.
###############################################################################

data "aws_iam_policy_document" "firehose_trust" {
  statement {
    sid     = "FirehoseAssumeRole"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }

    # `aws:SourceAccount` confused-deputy guard — only OUR account's Firehose
    # service may assume this role on our behalf.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "firehose" {
  provider             = aws.us_east_1
  name                 = "${var.name_prefix}-waf-firehose-role"
  description          = "Firehose role for WAF log delivery to S3 with Parquet conversion."
  assume_role_policy   = data.aws_iam_policy_document.firehose_trust.json
  max_session_duration = 3600
  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-waf-firehose-role"
    Component = "waf-logs"
  })
}

data "aws_iam_policy_document" "firehose_permissions" {
  # ---------------------------------------------------------------------------
  # S3 — list/get bucket metadata + write objects + abort multipart uploads.
  # ---------------------------------------------------------------------------
  statement {
    sid = "S3BucketLevel"
    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
    ]
    resources = [local.s3_bucket_arn]
  }

  statement {
    sid = "S3ObjectLevel"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetObject",
      "s3:PutObject",
      "s3:PutObjectAcl",
    ]
    resources = ["${local.s3_bucket_arn}/*"]
  }

  # ---------------------------------------------------------------------------
  # KMS — encrypt records with the customer-managed key BEFORE Firehose drops
  # them in S3, and decrypt data on subsequent re-reads.
  # ---------------------------------------------------------------------------
  statement {
    sid = "KMSEncryptDecrypt"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = [local.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }

  # ---------------------------------------------------------------------------
  # Glue — Firehose reads the destination table schema from the Glue catalog
  # for the JSON -> Parquet record format conversion.
  # ---------------------------------------------------------------------------
  statement {
    sid = "GlueCatalogRead"
    actions = [
      "glue:GetTable",
      "glue:GetTableVersion",
      "glue:GetTableVersions",
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:catalog",
      aws_glue_catalog_database.waf_logs.arn,
      "arn:${data.aws_partition.current.partition}:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/${aws_glue_catalog_database.waf_logs.name}/${aws_glue_catalog_table.waf_logs.name}",
    ]
  }

  # ---------------------------------------------------------------------------
  # CloudWatch Logs — emit delivery errors so they don't go to /dev/null.
  # ---------------------------------------------------------------------------
  statement {
    sid = "CloudWatchLogsWrite"
    actions = [
      "logs:PutLogEvents",
    ]
    resources = [
      "${aws_cloudwatch_log_group.firehose.arn}:*",
    ]
  }
}

resource "aws_iam_policy" "firehose" {
  provider    = aws.us_east_1
  name        = "${var.name_prefix}-waf-firehose-policy"
  description = "Permissions for the WAF-logs Firehose delivery role."
  policy      = data.aws_iam_policy_document.firehose_permissions.json
  tags        = var.tags
}

resource "aws_iam_role_policy_attachment" "firehose" {
  provider   = aws.us_east_1
  role       = aws_iam_role.firehose.name
  policy_arn = aws_iam_policy.firehose.arn
}

###############################################################################
# Kinesis Data Firehose delivery stream — extended S3 destination with:
#   - Dynamic partitioning (year/month/day/hour) via inline metadata extraction
#   - Record format conversion: JSON -> Parquet using the Glue table schema
#   - Server-side encryption with our customer-managed KMS key
#   - Buffer 64 MB / 60 s — balanced for typical WAF traffic on edge workloads
###############################################################################

resource "aws_kinesis_firehose_delivery_stream" "waf_logs" {
  provider    = aws.us_east_1
  name        = local.firehose_name
  destination = "extended_s3"

  # Server-side encryption of any in-stream records (in addition to the S3
  # SSE-KMS already applied at rest).
  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = local.kms_key_arn
  }

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose.arn
    bucket_arn          = local.s3_bucket_arn
    prefix              = local.s3_prefix
    error_output_prefix = local.s3_error_prefix

    # Buffering — Firehose flushes once EITHER threshold is reached.
    buffering_size     = var.firehose_buffer_mb
    buffering_interval = var.firehose_buffer_seconds

    compression_format = "UNCOMPRESSED" # Parquet handles its own compression

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = aws_cloudwatch_log_stream.firehose_s3_delivery.name
    }

    # -----------------------------------------------------------------------
    # Dynamic partitioning — extract year/month/day/hour fields from each
    # record's `timestamp` field (WAF logs always include it as epoch ms)
    # using a `MetadataExtraction` processor. The fields are then referenced
    # in the S3 prefix above (`!{partitionKeyFromQuery:...}`).
    # -----------------------------------------------------------------------
    dynamic_partitioning_configuration {
      enabled        = true
      retry_duration = 300
    }

    processing_configuration {
      enabled = true

      # MetadataExtraction extracts partition keys via JQ from each JSON record.
      # WAF emits `timestamp` as Unix-epoch milliseconds; the JQ expression
      # converts it into year/month/day/hour partition keys.
      processors {
        type = "MetadataExtraction"

        parameters {
          parameter_name  = "JsonParsingEngine"
          parameter_value = "JQ-1.6"
        }

        parameters {
          parameter_name  = "MetadataExtractionQuery"
          parameter_value = "{year: (.timestamp/1000 | strftime(\"%Y\")), month: (.timestamp/1000 | strftime(\"%m\")), day: (.timestamp/1000 | strftime(\"%d\")), hour: (.timestamp/1000 | strftime(\"%H\"))}"
        }
      }

      # AppendDelimiterToRecord ensures records are newline-separated when
      # Firehose writes them out (necessary for Parquet conversion robustness
      # and for raw-JSON fallback when conversion fails).
      processors {
        type = "AppendDelimiterToRecord"

        parameters {
          parameter_name  = "Delimiter"
          parameter_value = "\\n"
        }
      }
    }

    # -----------------------------------------------------------------------
    # Record format conversion — JSON in, Parquet out. The Parquet schema is
    # read from the Glue table at format-conversion time.
    # -----------------------------------------------------------------------
    data_format_conversion_configuration {
      enabled = true

      input_format_configuration {
        deserializer {
          # OpenX is more forgiving of WAF's nested label structure than HiveJSON.
          open_x_json_ser_de {
            case_insensitive                         = false
            convert_dots_in_json_keys_to_underscores = false
          }
        }
      }

      output_format_configuration {
        serializer {
          parquet_ser_de {
            compression                   = "SNAPPY"
            enable_dictionary_compression = true
            block_size_bytes              = 268435456 # 256 MiB row-group
            page_size_bytes               = 1048576   # 1 MiB
            writer_version                = "V1"
          }
        }
      }

      schema_configuration {
        database_name = aws_glue_catalog_database.waf_logs.name
        role_arn      = aws_iam_role.firehose.arn
        table_name    = aws_glue_catalog_table.waf_logs.name
        region        = data.aws_region.current.name
        version_id    = "LATEST"
      }
    }

    # -----------------------------------------------------------------------
    # Disable source-record backup — we already keep the converted Parquet
    # forever (or until lifecycle expires it) and don't need a JSON twin.
    # -----------------------------------------------------------------------
    s3_backup_mode = "Disabled"
  }

  tags = merge(var.tags, {
    Name      = local.firehose_name
    Component = "waf-logs"
  })

  # Make sure the catalog database, table, and IAM role attachment exist
  # before Firehose tries to call them — Firehose validates at create time.
  depends_on = [
    aws_iam_role_policy_attachment.firehose,
    aws_glue_catalog_table.waf_logs,
  ]

  lifecycle {
    # The random_id suffix means a name change requires recreation; declaring
    # it here surfaces that intent and protects production from a stale plan.
    create_before_destroy = false
  }
}
