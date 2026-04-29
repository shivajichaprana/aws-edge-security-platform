###############################################################################
# WAF logs — Glue catalog (database + table + crawler).
#
# Day 35 (`feat(athena)`).
#
# Why both an explicit table AND a crawler?
#
#   - The EXPLICIT TABLE is what Firehose's record-format-conversion needs at
#     write time (`schema_configuration { table_name = ... }`). It defines
#     the canonical schema the Parquet writer enforces.
#
#   - The CRAWLER's job is purely to keep the partition projection up to date
#     (and detect schema drift if WAF adds a new top-level field in a future
#     release). It runs on a daily schedule and is non-destructive — we
#     scope it to UPDATE_IN_DATABASE only, not LOG so partitions are added
#     without rewriting the table.
#
# Athena queries against this table assume Hive-style partition keys
# (year/month/day/hour) — Firehose writes them as `year=YYYY/month=MM/...`
# in the S3 key, which Athena recognises automatically.
###############################################################################

###############################################################################
# Glue database.
###############################################################################

resource "aws_glue_catalog_database" "waf_logs" {
  provider     = aws.us_east_1
  name         = replace("${var.name_prefix}_waf_logs", "-", "_")
  description  = "Catalog for WAF v2 logs partitioned by year/month/day/hour."
  location_uri = "s3://${aws_s3_bucket.waf_logs.bucket}/waf-logs/"
}

###############################################################################
# Glue table — explicit schema, partitioned by date components.
#
# The schema below is the WAF v2 log envelope as documented at:
# https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html
#
# Fields we capture:
#   - timestamp (epoch ms)            -> bigint
#   - formatVersion                   -> int
#   - webaclId                        -> string (full ARN)
#   - terminatingRuleId               -> string
#   - terminatingRuleType             -> string  (REGULAR / RATE_BASED / GROUP / MANAGED_RULE_GROUP)
#   - action                          -> string  (ALLOW / BLOCK / COUNT / CAPTCHA / CHALLENGE)
#   - terminatingRuleMatchDetails     -> array<struct>
#   - httpSourceName                  -> string  (CF for CloudFront)
#   - httpSourceId                    -> string
#   - ruleGroupList                   -> array<struct>
#   - rateBasedRuleList               -> array<struct>
#   - nonTerminatingMatchingRules     -> array<struct>
#   - requestHeadersInserted          -> array<struct>
#   - responseCodeSent                -> int
#   - httpRequest                     -> struct
#   - labels                          -> array<struct>
#   - captchaResponse                 -> struct
#   - challengeResponse               -> struct
###############################################################################

resource "aws_glue_catalog_table" "waf_logs" {
  provider      = aws.us_east_1
  name          = "waf_logs"
  database_name = aws_glue_catalog_database.waf_logs.name
  description   = "WAF v2 logs in Parquet, partitioned by year/month/day/hour."
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL              = "TRUE"
    "parquet.compression" = "SNAPPY"
    classification        = "parquet"

    # Hive-style partition projection — Athena auto-discovers partitions
    # without needing a crawler refresh. This keeps recent-data queries fast
    # and removes a class of "where are my partitions?" bugs.
    "projection.enabled"           = "true"
    "projection.year.type"         = "integer"
    "projection.year.range"        = "2026,2099"
    "projection.month.type"        = "integer"
    "projection.month.range"       = "1,12"
    "projection.month.digits"      = "2"
    "projection.day.type"          = "integer"
    "projection.day.range"         = "1,31"
    "projection.day.digits"        = "2"
    "projection.hour.type"         = "integer"
    "projection.hour.range"        = "0,23"
    "projection.hour.digits"       = "2"
    "storage.location.template"    = "s3://${aws_s3_bucket.waf_logs.bucket}/waf-logs/year=$${year}/month=$${month}/day=$${day}/hour=$${hour}/"
  }

  partition_keys {
    name = "year"
    type = "int"
  }
  partition_keys {
    name = "month"
    type = "int"
  }
  partition_keys {
    name = "day"
    type = "int"
  }
  partition_keys {
    name = "hour"
    type = "int"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.waf_logs.bucket}/waf-logs/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      name                  = "parquet"
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"

      parameters = {
        "serialization.format" = "1"
      }
    }

    columns {
      name = "timestamp"
      type = "bigint"
    }
    columns {
      name = "formatversion"
      type = "int"
    }
    columns {
      name = "webaclid"
      type = "string"
    }
    columns {
      name = "terminatingruleid"
      type = "string"
    }
    columns {
      name = "terminatingruletype"
      type = "string"
    }
    columns {
      name = "action"
      type = "string"
    }
    columns {
      name = "terminatingrulematchdetails"
      type = "array<struct<conditiontype:string,location:string,matcheddata:array<string>>>"
    }
    columns {
      name = "httpsourcename"
      type = "string"
    }
    columns {
      name = "httpsourceid"
      type = "string"
    }
    columns {
      name = "rulegrouplist"
      type = "array<struct<rulegroupid:string,terminatingrule:struct<ruleid:string,action:string>,nonterminatingmatchingrules:array<struct<ruleid:string,action:string>>,excludedrules:array<struct<exclusiontype:string,ruleid:string>>>>"
    }
    columns {
      name = "ratebasedrulelist"
      type = "array<struct<ratebasedruleid:string,limitkey:string,maxrateallowed:int>>"
    }
    columns {
      name = "nonterminatingmatchingrules"
      type = "array<struct<ruleid:string,action:string,rulematchdetails:array<struct<conditiontype:string,location:string,matcheddata:array<string>>>>>"
    }
    columns {
      name = "requestheadersinserted"
      type = "array<struct<name:string,value:string>>"
    }
    columns {
      name = "responsecodesent"
      type = "int"
    }
    columns {
      name = "httprequest"
      type = "struct<clientip:string,country:string,headers:array<struct<name:string,value:string>>,uri:string,args:string,httpversion:string,httpmethod:string,requestid:string>"
    }
    columns {
      name = "labels"
      type = "array<struct<name:string>>"
    }
    columns {
      name = "captcharesponse"
      type = "struct<responsecode:int,solvetimestamp:bigint,failurereason:string>"
    }
    columns {
      name = "challengeresponse"
      type = "struct<responsecode:int,solvetimestamp:bigint,failurereason:string>"
    }
  }
}

###############################################################################
# Glue crawler IAM role.
###############################################################################

data "aws_iam_policy_document" "glue_trust" {
  statement {
    sid     = "GlueAssumeRole"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["glue.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "glue_crawler" {
  provider           = aws.us_east_1
  name               = "${var.name_prefix}-waf-logs-crawler-role"
  description        = "Role used by the WAF-logs Glue crawler to list S3 + update the catalog."
  assume_role_policy = data.aws_iam_policy_document.glue_trust.json
  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-waf-logs-crawler-role"
    Component = "waf-logs"
  })
}

# AWS-managed policy gives the crawler the standard CloudWatch + Glue catalog
# access it needs. We supplement with a tightly-scoped S3 read policy.
resource "aws_iam_role_policy_attachment" "glue_service" {
  provider   = aws.us_east_1
  role       = aws_iam_role.glue_crawler.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSGlueServiceRole"
}

data "aws_iam_policy_document" "glue_s3_read" {
  statement {
    sid = "S3ReadLogs"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = [
      aws_s3_bucket.waf_logs.arn,
      "${aws_s3_bucket.waf_logs.arn}/*",
    ]
  }

  statement {
    sid = "KMSDecryptForGlue"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.waf_logs.arn]
  }
}

resource "aws_iam_policy" "glue_s3_read" {
  provider = aws.us_east_1
  name     = "${var.name_prefix}-waf-logs-crawler-s3-read"
  policy   = data.aws_iam_policy_document.glue_s3_read.json
  tags     = var.tags
}

resource "aws_iam_role_policy_attachment" "glue_s3_read" {
  provider   = aws.us_east_1
  role       = aws_iam_role.glue_crawler.name
  policy_arn = aws_iam_policy.glue_s3_read.arn
}

###############################################################################
# Glue crawler — daily schedule, schema-drift detection, never deletes.
#
# Although partition projection makes this less critical (Athena finds new
# partitions automatically), the crawler still serves two useful purposes:
#   1. Detects schema drift if AWS adds a new top-level WAF field. The
#      crawler updates the table; downstream alerting picks up the change.
#   2. Keeps the explicit (non-projected) partition list as a backup for
#      tools that don't honour partition projection (older Spark builds).
###############################################################################

resource "aws_glue_crawler" "waf_logs" {
  provider      = aws.us_east_1
  name          = "${var.name_prefix}-waf-logs-crawler"
  description   = "Daily crawler for WAF logs — keeps the catalog table in sync with on-disk Parquet."
  database_name = aws_glue_catalog_database.waf_logs.name
  role          = aws_iam_role.glue_crawler.arn

  s3_target {
    path = "s3://${aws_s3_bucket.waf_logs.bucket}/waf-logs/"
  }

  # Daily at 04:00 UTC — runs while traffic is lowest in most regions, so the
  # crawler avoids contending with peak Firehose write volume.
  schedule = "cron(0 4 * * ? *)"

  schema_change_policy {
    update_behavior = "UPDATE_IN_DATABASE"
    delete_behavior = "LOG" # never auto-delete partitions
  }

  recrawl_policy {
    # Only crawl objects added since the last run — fast and idempotent.
    recrawl_behavior = "CRAWL_NEW_FOLDERS_ONLY"
  }

  configuration = jsonencode({
    Version = 1.0
    Grouping = {
      TableGroupingPolicy = "CombineCompatibleSchemas"
    }
    CrawlerOutput = {
      Partitions = {
        AddOrUpdateBehavior = "InheritFromTable"
      }
    }
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-waf-logs-crawler"
    Component = "waf-logs"
  })

  depends_on = [
    aws_iam_role_policy_attachment.glue_service,
    aws_iam_role_policy_attachment.glue_s3_read,
    aws_glue_catalog_table.waf_logs,
  ]
}
