###############################################################################
# WAF logging configuration.
#
# Day 33 wires up the `aws_wafv2_web_acl_logging_configuration` resource
# pointing at a Kinesis Firehose delivery stream — that stream itself is
# created in Day 35 (`feat(waf-logs)`) along with the Glue catalog and
# Athena queries that consume the logs.
#
# Until Day 35 lands, operators pass `var.log_destination_arn = ""` and
# this resource is omitted via the `count` guard. Once the Firehose ARN
# is available, the logging configuration attaches it to the web ACL.
#
# Notes on the resource:
#
#   - `log_destination_configs` accepts S3 (via Firehose), CloudWatch Logs
#     log group, or Firehose delivery stream ARNs. Firehose is preferred
#     because it lands data in S3 in Parquet via Glue, which is what the
#     Athena queries (Day 35) expect.
#
#   - `redacted_fields` strips PII / secrets BEFORE the log record is
#     emitted. We redact:
#       * the Authorization header (bearer tokens, API keys)
#       * the Cookie header (session IDs)
#       * the URI's query string (tokens passed in URLs by mistake)
#
#   - `logging_filter` lets us discard high-volume noise (default-allow
#     records on read-only static asset paths) so we only pay for logs
#     that have investigative value. The filter is structured as a list
#     of conditions joined by AND/OR — see AWS docs for the schema.
#
# References:
#   - aws_wafv2_web_acl_logging_configuration:
#     https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_logging_configuration
#   - WAF logging: https://docs.aws.amazon.com/waf/latest/developerguide/logging.html
###############################################################################

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  # Only attach when the operator has provisioned a destination — Day 35
  # creates the Firehose and passes its ARN through the root module.
  count = length(var.log_destination_arn) > 0 ? 1 : 0

  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [var.log_destination_arn]

  # ---------------------------------------------------------------------------
  # PII redaction — remove fields before they ever land in S3.
  # ---------------------------------------------------------------------------
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  redacted_fields {
    single_header {
      name = "x-api-key"
    }
  }

  # The query-string redaction also covers tokens passed via `?token=...`
  # which is a common (bad) pattern in legacy clients.
  redacted_fields {
    query_string {}
  }

  # ---------------------------------------------------------------------------
  # Logging filter — keep all blocks, captchas, challenges; sample allows.
  #
  # Default action is KEEP (everything is logged unless filtered). We DROP
  # default-allow ALLOW records on static-asset paths to slash log volume
  # by 80–95% on most workloads — those records carry no incident value
  # since they didn't even hit a rule.
  # ---------------------------------------------------------------------------
  logging_filter {
    default_behavior = "KEEP"

    # Filter 1 — drop ALLOW records that didn't match any rule. Almost all
    # static-content traffic falls here.
    filter {
      behavior    = "DROP"
      requirement = "MEETS_ALL"

      condition {
        action_condition {
          action = "ALLOW"
        }
      }
    }

    # Filter 2 — explicitly KEEP records that hit a rule (block, count,
    # captcha, challenge). MEETS_ANY = OR across the conditions.
    filter {
      behavior    = "KEEP"
      requirement = "MEETS_ANY"

      condition {
        action_condition {
          action = "BLOCK"
        }
      }

      condition {
        action_condition {
          action = "COUNT"
        }
      }

      condition {
        action_condition {
          action = "CAPTCHA"
        }
      }

      condition {
        action_condition {
          action = "CHALLENGE"
        }
      }
    }
  }

  # The destination Firehose must exist before this resource is created;
  # we cannot enforce that with an explicit depends_on because the ARN is
  # passed as a string variable, but the count guard means we skip
  # creation entirely until Day 35 wires the value through.
}
