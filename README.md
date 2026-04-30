# aws-edge-security-platform

[![Terraform CI](https://github.com/shivajichaprana/aws-edge-security-platform/actions/workflows/terraform-ci.yml/badge.svg)](https://github.com/shivajichaprana/aws-edge-security-platform/actions/workflows/terraform-ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Terraform](https://img.shields.io/badge/Terraform-%3E%3D1.5-7B42BC?logo=terraform)](https://www.terraform.io/)
[![AWS Provider](https://img.shields.io/badge/AWS%20Provider-%3E%3D5.0-FF9900?logo=amazonaws)](https://registry.terraform.io/providers/hashicorp/aws/latest)

A production-grade, fully-Terraform-managed CloudFront edge security platform for protecting public web workloads against L7 attacks, scrapers, credential-stuffing bots, and abusive traffic. Includes WAFv2 with managed and custom rule sets, Bot Control with CAPTCHA/challenge actions, Lambda@Edge security headers and geo-routing, and a Kinesis-Firehose-to-Athena WAF log analytics pipeline.

## Architecture

```mermaid
flowchart LR
    Viewer[End User]
    Viewer -->|HTTPS / TLS 1.2+| CFFn[CloudFront Function<br/>URL rewrite]
    CFFn --> CF[CloudFront Distribution]
    CF -->|viewer-request| LE1[Lambda@Edge<br/>geo-router + headers]
    CF -->|origin-response| LE2[Lambda@Edge<br/>security-headers]
    CF --> WAF[WAFv2 Web ACL]
    WAF --> MGD[Managed Rule Groups<br/>Common, KnownBad, Linux,<br/>SQLi, IP-Rep, Anonymous-IP]
    WAF --> BOT[Bot Control<br/>CAPTCHA / Challenge]
    WAF --> CUST[Custom Rules<br/>rate-limit, geo-block,<br/>path/UA blocks]
    CF --> ALB[Application Load Balancer<br/>regional origin]
    ALB --> APP[(Origin Application)]

    WAF -.->|sampled requests| FH[Kinesis Firehose<br/>Parquet conversion]
    FH --> S3[S3 WAF Logs<br/>Glacier transition]
    S3 --> GLUE[Glue Catalog]
    GLUE --> ATH[Athena<br/>saved queries]
    ATH --> ANALYST[Security Analyst]

    classDef edge fill:#ff9900,color:#000,stroke:#222,stroke-width:1px
    classDef sec fill:#d13212,color:#fff,stroke:#222,stroke-width:1px
    classDef data fill:#3b48cc,color:#fff,stroke:#222,stroke-width:1px
    class CF,CFFn,LE1,LE2 edge
    class WAF,MGD,BOT,CUST sec
    class FH,S3,GLUE,ATH data
```

## Module reference

| Module | Path | Purpose |
|---|---|---|
| `cloudfront` | `terraform/modules/cloudfront` | CloudFront distribution with ALB origin, OAC, custom error pages, viewer-protocol redirect, modern TLS policy, Lambda@Edge + CF-Function associations. |
| `waf` | `terraform/modules/waf` | WAFv2 web ACL with AWS managed rule groups (Common, Known Bad Inputs, Linux, SQLi, IP Reputation, Anonymous IP), custom rate-limit rules, geo-block, path/UA blocks, and Bot Control with CAPTCHA. |
| `lambda-edge` | `terraform/modules/lambda-edge` | Three Lambda@Edge functions: `security-headers` (HSTS, CSP, X-Frame-Options, COEP, COOP), `geo-router` (rewrite path by viewer country), `header-rewrite` (origin request scrubber). Plus a CloudFront Function for path-rewrite. |
| `waf-logs` | `terraform/modules/waf-logs` | Kinesis Firehose with native Parquet conversion → S3 (with lifecycle to Glacier) → Glue catalog → Athena saved queries for top-blocked IPs, top-blocked URIs, bot-traffic ratio, country breakdown, and rule-hit drill-downs. |

## Quick start

> **Prerequisites:** Terraform `>= 1.5`, AWS provider `>= 5.0`, AWS account with permissions to create CloudFront, WAFv2, Lambda@Edge (in `us-east-1`), Kinesis Firehose, S3, Glue, Athena. An ACM certificate in `us-east-1` for your domain (CloudFront requirement). An Application Load Balancer to use as the origin.

```bash
# 1. Clone
git clone https://github.com/shivajichaprana/aws-edge-security-platform.git
cd aws-edge-security-platform

# 2. Configure
cp .env.example .env                # adjust as needed
cd terraform
cat > terraform.tfvars <<EOF
project_name        = "edge-prod"
aws_region          = "us-east-1"
domain_name         = "www.example.com"
acm_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/abc-123"
origin_alb_dns      = "alb-prod-1234567890.us-east-1.elb.amazonaws.com"
allowed_countries   = ["US", "GB", "IN", "AU", "DE", "FR", "NL", "CA"]
rate_limit_per_5min = 2000
enable_bot_control  = true
log_retention_days  = 365
EOF

# 3. Plan + apply
make init
make plan
make apply

# 4. Validate
make test
```

## Tuning guide

### Rate-limit rules

Default: `2000 requests per 5-minute window per IP`. Tune in `terraform.tfvars` via `rate_limit_per_5min`.

| Workload type | Recommended limit |
|---|---|
| Public marketing site | 2000 / 5min |
| Authenticated dashboard | 1000 / 5min |
| API gateway | 5000 / 5min (per IP) + 50/s burst |
| Anonymous browse + search | 3000 / 5min |

Hit the WAF logs in Athena (`saved-queries/top-rate-limited-ips.sql`) to validate. If you see >1% of legitimate users blocked, raise the limit by 50%.

### Bot Control sensitivity

Bot Control has three inspection levels: `COMMON`, `TARGETED_AGGRESSIVE`, `TARGETED_PROTECTION`. Defaults to `COMMON`. Switch to `TARGETED_AGGRESSIVE` when:

- Inventory hoarding (sneakers, ticketing) attacks observed.
- Credential stuffing across login endpoints (>5% failed-login spikes).
- Scraping pressure on pricing/product endpoints.

CAPTCHA is enforced via `aws_wafv2_web_acl.bot_control_rule` (see `terraform/modules/waf/bot_control.tf`). Token TTL is 300s by default; lengthen for low-friction UX.

### Geo-blocking

`allowed_countries` accepts ISO 3166-1 alpha-2 codes. Empty list disables geo-blocking. To allow-list:

```hcl
allowed_countries = ["US", "CA", "GB", "AU", "NL"]
```

To block specific countries (deny-list mode), set `geo_match_action = "block"` in the WAF module.

### WAF logs / Athena

Saved queries live in `terraform/modules/waf-logs/athena.tf` and `docs/athena-queries.md`:

- Top blocked IPs by hour.
- Top blocked URIs.
- Bot-Control-categorised vs. self-identified traffic.
- Rule-group hit distribution.

Partition the table by `year/month/day/hour` (already configured) and run `MSCK REPAIR TABLE` daily via the Glue crawler schedule.

## Repository layout

```
.
├── .github/workflows/terraform-ci.yml   # CI: fmt, validate, tflint, checkov, trivy, shellcheck
├── terraform/
│   ├── main.tf                          # Root composition: cloudfront + waf + waf-logs + lambda-edge
│   ├── variables.tf, outputs.tf, versions.tf
│   ├── .tflint.hcl
│   └── modules/
│       ├── cloudfront/
│       ├── waf/                         # main, rate_limit, bot_control, custom_rules, logging
│       ├── lambda-edge/
│       └── waf-logs/                    # firehose, s3, glue, athena
├── lambda-edge/
│   ├── security-headers/
│   ├── geo-router/
│   └── header-rewrite/
├── cloudfront-functions/                # url-rewrite
├── scripts/deploy.sh                    # Wrapper for init/plan/apply/destroy
├── docs/
│   ├── architecture.md                  # Architecture decisions
│   ├── runbook.md                       # On-call: DDoS, rate-limit tuning, IP blocking
│   ├── athena-queries.md
│   └── bot-control-guide.md
├── tests/                               # Terraform native tests
├── Makefile
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

## Cost considerations

| Component | Approximate monthly cost (10M requests, 1TB transfer) |
|---|---|
| CloudFront | $85 – $120 |
| WAFv2 (rules + requests) | $25 + $5 (managed groups) + $1/million |
| WAF Bot Control | $10 + $1/million inspected |
| Lambda@Edge | $0.60/million invocations + duration |
| Kinesis Firehose + S3 + Glue + Athena | ~$15 (logs <100GB/mo) |

Use the `cost_alarm_monthly_usd` variable to set a CloudWatch billing alarm.

## Security defaults

- TLS 1.2+ enforced (modern policy `TLSv1.2_2021`).
- HSTS preload, CSP, X-Frame-Options, X-Content-Type-Options injected via Lambda@Edge.
- Origin Access Control (OAC) used where origin is S3.
- WAF logging always-on, with Parquet compression and 365-day retention.
- IAM least-privilege (each Lambda has a dedicated role).
- All S3 buckets: blocked public access, AES-256 SSE, versioning, lifecycle.
- WAFv2 default action is `block` for the geo-block list and `allow` for whitelisted regions.

## Documentation

- [Architecture decisions](docs/architecture.md)
- [On-call runbook](docs/runbook.md)
- [Athena query catalogue](docs/athena-queries.md)
- [Bot Control tuning guide](docs/bot-control-guide.md)
- [Contributing](CONTRIBUTING.md)

## License

[MIT](LICENSE) © Shivaji Chaprana
