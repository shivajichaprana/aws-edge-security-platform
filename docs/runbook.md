# On-call Runbook

This runbook covers the most common incidents the edge-security platform is exercised by. Each section follows: **Detect → Triage → Mitigate → Communicate → Post-incident**.

> **Escalation:** Severity 1 (customer-impacting outage) — page security-on-call immediately. Severity 2 (degraded but partial) — open a war-room within 15 minutes. Severity 3 (latent risk) — a regular ticket suffices.

---

## 1. DDoS / volumetric attack response

### Detect

- CloudWatch alarm `cf-error-rate-5m` > 1% for 3 consecutive datapoints.
- AWS Shield event in the Shield console (always check this first when the WAF is "blocking everything").
- Origin alarm: ALB `RequestCountPerTarget` > 2× baseline.
- Customer reports of slow responses or 5xx errors.

### Triage

```bash
# 1. Confirm CloudFront is receiving the traffic (not the origin directly)
aws cloudwatch get-metric-statistics \
  --namespace AWS/CloudFront \
  --metric-name Requests \
  --dimensions Name=DistributionId,Value="$DIST_ID" Name=Region,Value=Global \
  --start-time "$(date -u -d '15 minutes ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --end-time   "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --period 60 --statistics Sum

# 2. Check WAF rule-hit distribution (find which rule is firing)
aws wafv2 get-sampled-requests \
  --web-acl-arn "$WAF_ARN" --rule-metric-name AnyHit \
  --scope CLOUDFRONT --time-window StartTime=...,EndTime=... --max-items 100

# 3. Run the Athena query for top blocked IPs in the last hour
#    See terraform/modules/waf-logs/athena.tf — saved query: top-blocked-ips
```

### Mitigate

1. **First action — increase rate limits to the most aggressive setting.** Lower `rate_limit_per_5min` to `500` for the affected URI pattern. This is reversible and low-risk.
2. **If a single ASN is responsible** — add an IP-set block for the source CIDRs. Use the `blocked_cidrs` variable.
3. **If geographically concentrated** — temporarily add the source country to the geo-block list.
4. **If still failing** — engage AWS Shield Response Team (Shield Advanced subscribers only). Open a Severity 1 case with phrase "DDoS in progress".

### Communicate

- Post to `#incidents` Slack channel within 5 minutes of confirmation.
- Status page update within 10 minutes.
- Hourly updates until resolved.

### Post-incident

- Capture pcap-equivalent (Athena export of the attack traffic).
- Open a ticket to bake the rate-limit / geo-block / IP-set into the steady-state Terraform.
- Schedule a blameless review within 5 business days.

---

## 2. Rate-limit tuning (false positives)

### Detect

- Athena query `false-positive-rate-by-rule.sql` returns >1% legitimate-looking blocks.
- Customer support escalations: "I'm getting 403 errors after refresh".

### Triage

1. Run `top-blocked-ips-with-history.sql` — a legitimate user typically has prior `allow` events from the same IP within 24h.
2. Cross-reference user-agent — bots usually have empty or generic UAs; a real user has a current Chrome/Safari/Firefox UA.
3. Inspect the `terminating_rule_id` in the WAF logs — confirms which rule is over-firing.

### Mitigate

- For the rate-limit rule: raise `rate_limit_per_5min` by 50% in `terraform.tfvars`, run `make plan` and `make apply`. CloudFront propagation takes ~5–10 minutes.
- For a managed-rule false positive: switch the rule action from `block` to `count` while you investigate. Use the `excluded_rules` map in the WAF module.
- For one-off customer issues: add their IP to the `allow_listed_cidrs` variable.

### Communicate

- Reply to the customer with the corrected rate-limit and an ETA for propagation.
- Post a `#incidents` recap with the rule that was tuned and the new value.

---

## 3. Blocking a specific abusive source

### Detect

- Athena query: `top-blocked-uris.sql` reveals a single source hammering a sensitive endpoint (e.g. `/api/login`, `/admin`).
- WAF rule logs show >1000 events from a single IP within 5 minutes.

### Mitigate

```bash
# 1. Add the IP to the deny IP-set (idempotent: append, do not replace)
cd terraform
# Edit terraform.tfvars:
# blocked_cidrs = ["203.0.113.10/32", "198.51.100.0/24", "<new-cidr>/32"]

# 2. Apply — the IP-set update propagates in seconds (much faster than a full WAF apply)
make plan
make apply
```

For an emergency block (no time to wait for CI):

```bash
# Direct API call to update the IP-set
aws wafv2 update-ip-set \
  --scope CLOUDFRONT \
  --name "$IPSET_NAME" --id "$IPSET_ID" --lock-token "$TOKEN" \
  --addresses 203.0.113.10/32 198.51.100.0/24
```

> **Warning:** drift this back into Terraform within 24 hours, otherwise the next `terraform apply` will overwrite the manual change.

### Communicate

- Note the block in `#security-actions`.
- File a ticket for follow-up: identify the actor (ASN, geo, behaviour) and decide whether to maintain the block long-term.

---

## 4. WAF logs not arriving in S3 / Athena

### Detect

- Athena query returns no rows for the last 30 minutes despite live traffic.
- CloudWatch metric `aws:firehose:DeliveryToS3.Records` is at 0.

### Triage

1. Confirm WAF logging is enabled: `aws wafv2 get-logging-configuration --resource-arn "$WAF_ARN"`.
2. Confirm Firehose stream status: `aws firehose describe-delivery-stream --delivery-stream-name "$STREAM_NAME"`.
3. Check Firehose error logs in the configured S3 error prefix.
4. Check IAM role permissions on the Firehose role — must allow `s3:PutObject` and `glue:GetTable` (for record-format-conversion).

### Mitigate

- If the conversion is failing: temporarily disable Parquet conversion (`record_format_conversion = false`) — logs will land as JSON.gz, ugly but visible.
- If the Glue table schema drifted: re-run the crawler `aws glue start-crawler --name "$CRAWLER_NAME"` and re-apply Terraform to align.
- If the IAM role is broken: roll back the most recent change to `terraform/modules/waf-logs/firehose.tf`.

### Post-incident

- Add a CloudWatch alarm on `Firehose.IncomingRecords` with a `LessThanThreshold` of `1` for 15 minutes. Alarm into `#incidents`.

---

## 5. Bot Control / CAPTCHA loops

### Detect

- Customer reports "I keep getting CAPTCHA over and over".
- Athena query `bot-control-actions-by-ip.sql` shows the same IP receiving CAPTCHA challenges repeatedly without a successful token.

### Triage

1. Confirm Bot Control is in `TARGETED_AGGRESSIVE` mode (CAPTCHA is most likely to over-fire here).
2. Inspect the user's UA — older browsers, headless tooling, and accessibility tools often fail Bot Control's signal collection.

### Mitigate

- Lower the inspection level back to `COMMON` — covers >95% of bots without the FN risk.
- Lengthen the CAPTCHA token TTL: `captcha_token_ttl_seconds = 600`.
- For a specific user — add their IP to `allow_listed_cidrs` (temporary; expire after 7 days).

---

## 6. CloudFront → ALB origin failover

### Detect

- ALB-side 5xx rate > 5% for 3 minutes.
- CloudFront metric `OriginLatency` > 3s.

### Triage

- Confirm the origin's `/health` endpoint is responsive.
- Check ALB target-group health.
- If the origin is down, CloudFront will serve cached content for the configured `default_ttl` window.

### Mitigate

1. **If the issue is a single AZ** — ALB will fail over automatically; nothing to do.
2. **If the issue is the entire region** — flip the origin DNS in Route 53 to a DR region (out of scope for this repo but documented in `aws-backup-dr`).
3. **If the issue is application-layer** — engage the application on-call.

---

## Appendix — useful one-liners

```bash
# Tail CloudFront access logs in real-time (requires standard CF logs to S3 enabled)
aws s3 cp "s3://$CF_LOG_BUCKET/$DIST_ID/" - --recursive --exclude '*' --include "*$(date -u +%Y-%m-%d-%H)*" | gunzip

# Force invalidation
aws cloudfront create-invalidation --distribution-id "$DIST_ID" --paths "/*"

# Show current WAF rule-action mapping
aws wafv2 get-web-acl --scope CLOUDFRONT --name "$WAF_NAME" --id "$WAF_ID" \
  | jq '.WebACL.Rules[] | {name: .Name, action: (.Action // .OverrideAction)}'
```
