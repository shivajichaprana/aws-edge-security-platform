# Architecture Decisions

This document captures the key architecture decisions made while building `aws-edge-security-platform`. Each decision is recorded ADR-style: context → decision → consequences.

---

## ADR-001 — CloudFront as the single ingress for public web workloads

### Context

Public web workloads need TLS termination, edge caching, DDoS absorption, and a place to attach WAF rules and edge compute. AWS provides three primary edge ingress paths: CloudFront, Application Load Balancer with AWS WAF directly, and API Gateway.

### Decision

Use **CloudFront** as the single ingress for the platform.

Rationale:

1. CloudFront is integrated with AWS Shield Standard at no cost, and supports Shield Advanced for an additional fee — both ALB-direct and APIGW are also covered, but CloudFront absorbs L3/L4 closer to the source.
2. Lambda@Edge and CloudFront Functions allow request manipulation before any origin is touched.
3. Edge caching reduces origin pressure and origin-fetch cost.
4. WAFv2 at the CloudFront scope is regional-independent (`scope = "CLOUDFRONT"`) — one ACL protects every PoP.

### Consequences

- All Lambda@Edge functions must live in `us-east-1`. The provider in `terraform/main.tf` aliases a `us_east_1` provider for this reason.
- The ACM certificate must be in `us-east-1`. This is a hard CloudFront constraint.
- TTLs need careful tuning — too aggressive caching has caused stale-content incidents in past projects.

---

## ADR-002 — WAFv2 with managed rule groups + targeted custom rules

### Context

WAF protection has three options:
1. AWS Managed Rules — broad, low-effort, covers the OWASP Top 10 + bots + scanners.
2. Marketplace rules (Fortinet, Imperva, F5) — premium, higher quality on niche threats.
3. Hand-written custom rules — narrow but tunable.

### Decision

Combine **AWS Managed Rules** as the foundation with **custom rules** for application-specific concerns:

- **Managed groups (always on):** `AWSManagedRulesCommonRuleSet`, `AWSManagedRulesKnownBadInputsRuleSet`, `AWSManagedRulesLinuxRuleSet`, `AWSManagedRulesSQLiRuleSet`, `AWSManagedRulesAmazonIpReputationList`, `AWSManagedRulesAnonymousIpList`.
- **Bot Control (toggleable):** managed group with CAPTCHA + challenge actions.
- **Custom rules:** rate limiting (per-IP, per-5min), allow-listed paths (e.g. `/health`), geo-block, blocked user agents, blocked source IPs (CIDR sets).

Rationale:

- Managed groups are tuned by AWS and updated continuously; we get the threat-intelligence flywheel for ~$5/group/month.
- Custom rules let us encode local context (which paths are public, which IPs are partners, which countries we sell to).

### Consequences

- We must monitor false-positive rates from each managed group separately. The `docs/runbook.md` describes the disable-and-re-enable workflow.
- `count` action is used in initial rollout for any new rule group; `block` only after one week of clean sampled requests.

---

## ADR-003 — Lambda@Edge for security headers, CloudFront Functions for URL rewrites

### Context

CloudFront supports two flavours of edge compute:

| Feature | Lambda@Edge | CloudFront Functions |
|---|---|---|
| Languages | Node.js, Python | JS (subset of ES 5.1) |
| Cold start | ~50ms | ~1ms |
| Max execution | 5–30s | 1ms |
| Cost | $0.60/M + duration | $0.10/M |
| Available triggers | viewer-request, viewer-response, origin-request, origin-response | viewer-request, viewer-response only |
| Request/response body access | Yes | No |

### Decision

- **Security headers** (HSTS, CSP, X-Frame-Options, COEP, COOP) — Lambda@Edge `origin-response` trigger. Needs to inspect/modify origin responses; CF Functions can't.
- **Geo-routing** (rewrite path based on viewer country) — Lambda@Edge `viewer-request`. Needs the full event with `viewer-country` header.
- **Header rewrite** for origin requests (strip cookies before logging, rotate `X-Forwarded-For`) — Lambda@Edge `origin-request`.
- **URL rewrite** (e.g. `/about` → `/about.html`) — CloudFront Function, far cheaper at high request volume.

### Consequences

- Two replication workflows to manage (Lambda@Edge replicates to all regions; CF Functions deploy globally instantly).
- Lambda@Edge logs land in `us-east-1` *and* in regional CloudWatch — querying requires aggregation.

---

## ADR-004 — Kinesis Firehose with native Parquet conversion for WAF logs

### Context

WAFv2 supports three log destinations: CloudWatch Logs, S3 (via Firehose), and Kinesis Data Streams. We want to:

1. Retain logs cheaply for 1 year.
2. Run analytics with Athena.
3. Pay <$25/month for log infrastructure at moderate scale.

### Decision

**Kinesis Firehose → Parquet → S3 (Glacier transition) → Glue Catalog → Athena.**

Rationale:

- WAF logs are JSON-line; Firehose's record-format-conversion to Parquet shrinks them ~5x and dramatically improves Athena query performance.
- A Glue crawler refreshes partitions daily.
- S3 lifecycle moves objects >90 days to S3 Glacier Instant Retrieval, reducing storage cost ~70%.

### Consequences

- Conversion adds ~60 seconds latency from log emission to S3 object availability — acceptable for analytics, not for real-time alerting.
- For real-time alerting we rely on CloudWatch metrics emitted by WAF directly (rule-hit count, blocked-request count).

---

## ADR-005 — One Terraform state, one root module, multiple modules

### Context

Common patterns:

1. Many tiny states per module (Terragrunt-style).
2. One large monolithic state.
3. Layered states (network / security / compute) with `terraform_remote_state`.

### Decision

**One root module that composes the four child modules** (`cloudfront`, `waf`, `lambda-edge`, `waf-logs`). All inputs flow through `terraform.tfvars`.

Rationale:

- The platform is small (~5 modules, ~30 resources). The complexity of Terragrunt is unwarranted.
- Atomic apply prevents partial-deploy footguns (e.g. CloudFront association referencing a Lambda@Edge ARN that's been destroyed).
- A `make plan` shows the full blast radius in one place.

### Consequences

- Apply time is ~12 minutes (CloudFront propagation dominates). We accept this.
- The state file gets locked for everyone for the duration of an apply. We document this in `docs/runbook.md`.

---

## ADR-006 — Tag every resource with project, environment, and owner

### Context

AWS cost allocation, blast-radius queries, and IAM/SCP enforcement all need consistent tags.

### Decision

Use a **provider-level `default_tags`** block:

```hcl
provider "aws" {
  default_tags {
    tags = {
      project     = var.project_name
      environment = var.environment
      owner       = "platform-security"
      managed_by  = "terraform"
      repo        = "aws-edge-security-platform"
    }
  }
}
```

### Consequences

- Tags propagate automatically to every taggable resource.
- WAF Web ACLs do not honour `default_tags` for the underlying CloudWatch metric configuration — those are tagged explicitly.

---

## Future work

- Move state to S3 + DynamoDB lock with cross-account assume-role.
- Add CloudFront Continuous Deployment (staging distribution + traffic-weight transitions).
- Add Shield Advanced and DRT runbook (separate repo).
- Integrate WAF log feed into a SIEM via the Firehose subscription.
