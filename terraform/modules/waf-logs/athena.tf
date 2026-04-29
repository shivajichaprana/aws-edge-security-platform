###############################################################################
# WAF logs — Athena workgroup + named (saved) queries.
#
# Day 35 (`feat(athena)`).
#
# Workgroup pattern:
#
#   - SEPARATE results bucket — never write Athena query output back into the
#     log bucket. Two reasons: (a) keeps the immutable-audit posture clean,
#     and (b) Athena results in IA/Glacier is wasteful (the result bucket
#     uses a 7-day lifecycle).
#
#   - ENFORCE_WORKGROUP_CONFIGURATION = true means client-side overrides
#     (e.g. an analyst trying to send results to their personal bucket) are
#     blocked. This is critical for compliance — query output is governed
#     identically to source data.
#
#   - publish_cloudwatch_metrics_enabled = true gives us per-workgroup
#     QueryQueueTime / DataScanned metrics for cost monitoring.
#
# Saved queries:
#   1. top_blocked_ips
#   2. top_matched_rules
#   3. status_code_distribution
#   4. requests_by_country
#   5. captcha_pass_rate
#   6. uri_attack_distribution
#   7. anomalous_user_agents
#   8. rate_limit_hits_per_path
###############################################################################

###############################################################################
# Athena query results bucket.
###############################################################################

resource "aws_s3_bucket" "athena_results" {
  provider      = aws.us_east_1
  bucket        = "${var.name_prefix}-waf-athena-results-${random_id.bucket_suffix.hex}"
  force_destroy = true # query results are ephemeral by design

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-athena-results"
    Component = "waf-logs"
    DataClass = "query-output"
  })
}

resource "aws_s3_bucket_ownership_controls" "athena_results" {
  provider = aws.us_east_1
  bucket   = aws_s3_bucket.athena_results.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  provider                = aws.us_east_1
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  provider = aws.us_east_1
  bucket   = aws_s3_bucket.athena_results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.waf_logs.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  provider = aws.us_east_1
  bucket   = aws_s3_bucket.athena_results.id

  rule {
    id     = "expire-results-7d"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

###############################################################################
# Athena workgroup.
###############################################################################

resource "aws_athena_workgroup" "waf_logs" {
  provider      = aws.us_east_1
  name          = "${var.name_prefix}-waf-logs"
  description   = "Workgroup for WAF log analytics — queries the parquet table written by Firehose."
  state         = "ENABLED"
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = var.bytes_scanned_cutoff_bytes

    requester_pays_enabled = false

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.waf_logs.arn
      }
    }

    engine_version {
      selected_engine_version = "Athena engine version 3"
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-waf-logs-workgroup"
    Component = "waf-logs"
  })
}

###############################################################################
# Saved (NamedQuery) — Athena queries.
#
# Each query uses partition-pruning hints (year/month/day filters) so the
# bytes-scanned-cutoff doesn't accidentally bite. The placeholders are:
#   {DB}    = Glue database name (templated via `format`)
#   {TBL}   = `waf_logs` (constant)
#
# We render each query body with `format()` so the database name is the
# canonical one returned by the catalog rather than re-derived from inputs.
###############################################################################

locals {
  table_ref = "${aws_glue_catalog_database.waf_logs.name}.${aws_glue_catalog_table.waf_logs.name}"
}

resource "aws_athena_named_query" "top_blocked_ips" {
  provider    = aws.us_east_1
  name        = "01_top_blocked_ips"
  workgroup   = aws_athena_workgroup.waf_logs.id
  database    = aws_glue_catalog_database.waf_logs.name
  description = "Top 50 client IPs ranked by BLOCK actions over the last 24 hours."
  query       = <<-SQL
    -- Top blocked client IPs in the last 24 hours.
    -- Partition pruning: year/month/day = current UTC date and yesterday.
    SELECT
      httprequest.clientip                       AS client_ip,
      httprequest.country                        AS country,
      COUNT(*)                                   AS block_count,
      COUNT_IF(terminatingruletype = 'RATE_BASED') AS rate_based_blocks,
      MIN(from_unixtime(timestamp/1000))         AS first_seen_utc,
      MAX(from_unixtime(timestamp/1000))         AS last_seen_utc
    FROM ${local.table_ref}
    WHERE action = 'BLOCK'
      AND year  = CAST(year(current_date) AS int)
      AND month = CAST(month(current_date) AS int)
      AND day BETWEEN CAST(day(current_date) - 1 AS int) AND CAST(day(current_date) AS int)
    GROUP BY 1, 2
    ORDER BY block_count DESC
    LIMIT 50;
  SQL
}

resource "aws_athena_named_query" "top_matched_rules" {
  provider    = aws.us_east_1
  name        = "02_top_matched_rules"
  workgroup   = aws_athena_workgroup.waf_logs.id
  database    = aws_glue_catalog_database.waf_logs.name
  description = "Most-matched terminating rules — useful to spot rules that need tuning."
  query       = <<-SQL
    -- Top terminating rules (matched, blocked, or counted) over the last 24h.
    SELECT
      terminatingruleid                  AS rule_id,
      terminatingruletype                AS rule_type,
      action                             AS action,
      COUNT(*)                           AS match_count,
      COUNT(DISTINCT httprequest.clientip) AS unique_ips
    FROM ${local.table_ref}
    WHERE terminatingruleid != 'Default_Action'
      AND year  = CAST(year(current_date) AS int)
      AND month = CAST(month(current_date) AS int)
      AND day BETWEEN CAST(day(current_date) - 1 AS int) AND CAST(day(current_date) AS int)
    GROUP BY 1, 2, 3
    ORDER BY match_count DESC
    LIMIT 50;
  SQL
}

resource "aws_athena_named_query" "status_code_distribution" {
  provider    = aws.us_east_1
  name        = "03_status_code_distribution"
  workgroup   = aws_athena_workgroup.waf_logs.id
  database    = aws_glue_catalog_database.waf_logs.name
  description = "WAF response-code distribution — confirms 4xx/5xx ratio is in expected band."
  query       = <<-SQL
    -- Hourly distribution of response codes sent by WAF (action -> status mapping).
    SELECT
      date_trunc('hour', from_unixtime(timestamp/1000)) AS hour_utc,
      responsecodesent                                  AS status_code,
      action                                            AS action,
      COUNT(*)                                          AS request_count
    FROM ${local.table_ref}
    WHERE year  = CAST(year(current_date) AS int)
      AND month = CAST(month(current_date) AS int)
      AND day = CAST(day(current_date) AS int)
    GROUP BY 1, 2, 3
    ORDER BY hour_utc DESC, status_code, action;
  SQL
}

resource "aws_athena_named_query" "requests_by_country" {
  provider    = aws.us_east_1
  name        = "04_requests_by_country"
  workgroup   = aws_athena_workgroup.waf_logs.id
  database    = aws_glue_catalog_database.waf_logs.name
  description = "Requests broken down by viewer country — highlights geographic anomalies."
  query       = <<-SQL
    -- Requests by viewer country, with a block-rate column to expose
    -- low-traffic countries with abnormally high block percentages.
    SELECT
      httprequest.country                                          AS country,
      COUNT(*)                                                     AS total_requests,
      COUNT_IF(action = 'BLOCK')                                   AS blocked_requests,
      ROUND(100.0 * COUNT_IF(action = 'BLOCK') / COUNT(*), 2)      AS block_pct
    FROM ${local.table_ref}
    WHERE year  = CAST(year(current_date) AS int)
      AND month = CAST(month(current_date) AS int)
      AND day = CAST(day(current_date) AS int)
    GROUP BY 1
    HAVING COUNT(*) > 100
    ORDER BY total_requests DESC;
  SQL
}

resource "aws_athena_named_query" "captcha_pass_rate" {
  provider    = aws.us_east_1
  name        = "05_captcha_pass_rate"
  workgroup   = aws_athena_workgroup.waf_logs.id
  database    = aws_glue_catalog_database.waf_logs.name
  description = "CAPTCHA / challenge solve rates — indicates bot pressure and UX impact."
  query       = <<-SQL
    -- CAPTCHA & challenge solve rates per URI prefix in the last 24h.
    -- responsecode 0 means the user solved successfully (Solved); non-zero
    -- means the puzzle was failed or timed out.
    SELECT
      action                                                         AS action,
      regexp_extract(httprequest.uri, '^(/[^/?]*)', 1)                AS uri_root,
      COUNT(*)                                                       AS attempts,
      COUNT_IF(captcharesponse.responsecode = 0
               OR challengeresponse.responsecode = 0)                AS solved,
      ROUND(
        100.0 *
        COUNT_IF(captcharesponse.responsecode = 0 OR challengeresponse.responsecode = 0)
        / NULLIF(COUNT(*), 0),
        2
      )                                                              AS solve_pct
    FROM ${local.table_ref}
    WHERE action IN ('CAPTCHA', 'CHALLENGE')
      AND year  = CAST(year(current_date) AS int)
      AND month = CAST(month(current_date) AS int)
      AND day BETWEEN CAST(day(current_date) - 1 AS int) AND CAST(day(current_date) AS int)
    GROUP BY 1, 2
    HAVING COUNT(*) > 10
    ORDER BY attempts DESC;
  SQL
}

resource "aws_athena_named_query" "uri_attack_distribution" {
  provider    = aws.us_east_1
  name        = "06_uri_attack_distribution"
  workgroup   = aws_athena_workgroup.waf_logs.id
  database    = aws_glue_catalog_database.waf_logs.name
  description = "Top blocked URIs — points the IR team at which endpoints are under attack."
  query       = <<-SQL
    -- Top blocked URI roots (path/segment 1) in the last 24h.
    SELECT
      regexp_extract(httprequest.uri, '^(/[^/?]*)', 1)               AS uri_root,
      httprequest.httpmethod                                          AS method,
      COUNT(*)                                                        AS block_count,
      COUNT(DISTINCT httprequest.clientip)                            AS distinct_ips,
      array_agg(DISTINCT terminatingruleid)                           AS firing_rules
    FROM ${local.table_ref}
    WHERE action = 'BLOCK'
      AND year  = CAST(year(current_date) AS int)
      AND month = CAST(month(current_date) AS int)
      AND day BETWEEN CAST(day(current_date) - 1 AS int) AND CAST(day(current_date) AS int)
    GROUP BY 1, 2
    ORDER BY block_count DESC
    LIMIT 50;
  SQL
}

resource "aws_athena_named_query" "anomalous_user_agents" {
  provider    = aws.us_east_1
  name        = "07_anomalous_user_agents"
  workgroup   = aws_athena_workgroup.waf_logs.id
  database    = aws_glue_catalog_database.waf_logs.name
  description = "User-agent patterns associated with high block rates — bot signal."
  query       = <<-SQL
    -- Identify user-agent strings driving disproportionately high block rates.
    -- We extract User-Agent from the headers array and bucket by the first
    -- 80 chars (full strings explode cardinality).
    WITH ua AS (
      SELECT
        try(filter(httprequest.headers, h -> lower(h.name) = 'user-agent')[1].value)
          AS user_agent,
        action,
        httprequest.clientip AS ip
      FROM ${local.table_ref}
      WHERE year  = CAST(year(current_date) AS int)
        AND month = CAST(month(current_date) AS int)
        AND day = CAST(day(current_date) AS int)
    )
    SELECT
      coalesce(substr(user_agent, 1, 80), '<missing>')              AS user_agent_prefix,
      COUNT(*)                                                       AS total_requests,
      COUNT_IF(action = 'BLOCK')                                     AS blocked,
      ROUND(100.0 * COUNT_IF(action = 'BLOCK') / COUNT(*), 2)        AS block_pct,
      COUNT(DISTINCT ip)                                             AS distinct_ips
    FROM ua
    GROUP BY 1
    HAVING COUNT(*) > 50
       AND COUNT_IF(action = 'BLOCK') * 1.0 / COUNT(*) > 0.10
    ORDER BY blocked DESC
    LIMIT 100;
  SQL
}

resource "aws_athena_named_query" "rate_limit_hits_per_path" {
  provider    = aws.us_east_1
  name        = "08_rate_limit_hits_per_path"
  workgroup   = aws_athena_workgroup.waf_logs.id
  database    = aws_glue_catalog_database.waf_logs.name
  description = "Rate-limit rule hits broken down by URI — guides per-endpoint tuning."
  query       = <<-SQL
    -- Where are rate-limit blocks landing? Aggregates over rule + URI.
    SELECT
      terminatingruleid                                             AS rate_rule_id,
      regexp_extract(httprequest.uri, '^(/[^/?]*)', 1)              AS uri_root,
      COUNT(*)                                                      AS hits,
      COUNT(DISTINCT httprequest.clientip)                          AS unique_ips,
      MAX(from_unixtime(timestamp/1000))                            AS last_hit_utc
    FROM ${local.table_ref}
    WHERE terminatingruletype = 'RATE_BASED'
      AND year  = CAST(year(current_date) AS int)
      AND month = CAST(month(current_date) AS int)
      AND day BETWEEN CAST(day(current_date) - 1 AS int) AND CAST(day(current_date) AS int)
    GROUP BY 1, 2
    ORDER BY hits DESC
    LIMIT 50;
  SQL
}
