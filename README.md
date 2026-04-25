# aws-edge-security-platform

Terraform-driven AWS edge security stack: **CloudFront + AWS WAF + Lambda@Edge** with bot
control, AWS Shield baseline, and a Kinesis Firehose → Athena pipeline for WAF-log analytics.
Built to be applied as-is in front of an existing ALB, ECS service, or S3 origin.

> **Status:** Day 31 of 90 — repo bootstrap. CloudFront + baseline WAF web ACL ready.
> Subsequent days add managed rule groups, rate limiting, bot control, Lambda@Edge, and a
> log-analytics pipeline.

## Goals

1. Block obvious abuse at the edge before it reaches the origin (OWASP Top-10, scrapers,
   anonymous proxies, vulnerable HTTP libraries).
2. Add policy at the viewer-request layer with Lambda@Edge (security headers, geo routing).
3. Provide auditable evidence of every blocked request via WAF full-logs landing in S3 as
   partitioned Parquet, queryable through Athena.
4. Encode every piece of edge configuration as Terraform modules that any team can re-use.

## Architecture (target end-state)

```
                   +----------------+
                   |  Route 53 DNS  |
                   +-------+--------+
                           |
                           v
+------------+      +------+--------+      +-----------------+
|  Viewer    +----->+   CloudFront  +----->+    Origin       |
|  (browser) |      | + AWS WAF v2  |      | (ALB / S3 / API)|
+------------+      +------+--------+      +-----------------+
                           |
                           v
                +----------+----------+        +-----------------+
                | WAF logging         +------->+ Kinesis Firehose|
                | (full request log)  |        | (Parquet, dyn.  |
                +----------+----------+        |  partitioning)  |
                           |                    +--------+--------+
                           v                             |
                  +--------+---------+                   v
                  | Lambda@Edge      |          +--------+---------+
                  | viewer-request / |          |  S3 (raw + logs) |
                  | viewer-response  |          +--------+---------+
                  +------------------+                   |
                                                         v
                                              +----------+---------+
                                              |  Glue catalog +    |
                                              |  Athena queries    |
                                              +--------------------+
```

## Repository layout

```
aws-edge-security-platform/
├── terraform/
│   ├── main.tf                 # Root composition (calls modules)
│   ├── versions.tf             # Provider/Terraform version pins + aliases
│   ├── variables.tf            # Root-level inputs
│   ├── outputs.tf              # Root-level outputs
│   └── modules/
│       ├── cloudfront/         # CloudFront distribution + ALB origin wiring
│       └── waf/                # AWS WAFv2 web ACL with managed rule groups
├── lambda-edge/                # Lambda@Edge handlers (added Day 34)
├── cloudfront-functions/       # CloudFront Functions (added Day 34)
├── scripts/                    # deploy.sh, helpers (added Day 36)
├── docs/                       # architecture / runbook / Athena queries
├── .github/workflows/          # CI (added Day 36)
├── Makefile                    # init/plan/apply/test (added Day 36)
└── tests/                      # tftest HCL (added Day 32)
```

## Quick start (Day-31 baseline)

> Requires Terraform >= 1.6 and AWS credentials with permission to create
> CloudFront, WAFv2 (CLOUDFRONT scope), and ACM certs in **us-east-1**.

```bash
git clone https://github.com/shivajichaprana/aws-edge-security-platform.git
cd aws-edge-security-platform/terraform

cp ../.env.example ../.env
# edit ../.env to set ALB_DNS_NAME, ROOT_DOMAIN, PROJECT_NAME, ENVIRONMENT

terraform init
terraform plan \
  -var "project_name=edge-security" \
  -var "environment=dev" \
  -var "alb_dns_name=$ALB_DNS_NAME" \
  -var "root_domain=$ROOT_DOMAIN"
```

The Day-31 plan creates:
- 1 × `aws_cloudfront_distribution` (custom error pages, compression on, HTTP/2+HTTP/3).
- 1 × `aws_wafv2_web_acl` (CLOUDFRONT scope) with `AWSManagedRulesCommonRuleSet`,
  `KnownBadInputsRuleSet`, and `AWSManagedRulesSQLiRuleSet`.
- 1 × association between the WAF ACL and the CloudFront distribution.

## What's delivered today vs. coming next

| Day | Scope                                                                     |
|-----|---------------------------------------------------------------------------|
| 31  | Repo scaffold, CloudFront distribution, baseline WAF managed rule groups |
| 32  | Add Linux/IpRep/AnonIP managed groups + per-IP and per-URI rate limiting |
| 33  | AWSManagedRulesBotControlRuleSet (targeted), CAPTCHA + token challenge   |
| 34  | Lambda@Edge (security headers, geo routing) + CloudFront Functions       |
| 35  | Firehose + Glue + Athena pipeline for WAF logs                           |
| 36  | CI (terraform fmt/validate, tflint, checkov, trivy), runbook, v1.0.0     |

## Hard rules
- All commits authored solely by Shivaji Chaprana — no co-authors.
- One repo touched per day: this one only on Days 31–36.
- No changes to the GitHub profile README.

## License

MIT — see [LICENSE](./LICENSE).
