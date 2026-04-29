# Athena Queries for WAF Log Analytics

This catalogue documents every saved (NamedQuery) the `waf-logs` module
provisions, and provides ready-to-run *ad-hoc* queries you can paste into
the Athena console for incident investigations. All queries assume the
table created by `terraform/modules/waf-logs/glue.tf`:

```
<glue_database>.waf_logs
```

## Table & partitions (recap)

The table is partitioned on `(year, month, day, hour)` (all `int`). The
module enables Hive-style partition projection so Athena automatically
prunes scans to the relevant partitions — every query in this catalogue
*always* includes a partition filter to cap data-scanned cost. Athena
queries that omit partition filters are aborted by the workgroup's
`bytes_scanned_cutoff_per_query` quota.

The Parquet schema mirrors the [WAF v2 logging fields][waf-fields]:
`timestamp` (epoch ms), `webaclid`, `terminatingruleid`,
`terminatingruletype`, `action`, nested `httprequest`, `labels`,
`captcharesponse`, `challengeresponse`, etc.

[waf-fields]: https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html

---

## Saved queries (provisioned by the module)

### 1. `01_top_blocked_ips`

**What it tells you:** which client IPs are getting blocked the most over
the last 24 hours, broken out by country and rate-based-vs-other.

**When to use:** first-pass triage during a suspected DDoS or scraping
incident — feed the top-N IPs into the `blocked_ips` variable on the WAF
module to enforce a hard block.

**Cost:** scans 2 day partitions (yesterday + today). Typical scan: ~50 MB.

### 2. `02_top_matched_rules`

**What it tells you:** which terminating rules (managed or custom) fired
the most in the last 24h, by action.

**When to use:** weekly tuning review — a rule with very high match counts
relative to others may need its action lowered to `count` (false-positive
suspicion) or its priority raised. Look for `Default_Action` matches:
those mean *no* rule fired, which is normal for healthy traffic.

### 3. `03_status_code_distribution`

**What it tells you:** hourly distribution of HTTP status codes WAF sent
back, segmented by action. Healthy production usually shows a stable
ratio of 200/302/404 and a low-but-non-zero rate of 403 (BLOCK) and
405 (CAPTCHA).

**When to use:** baseline drift detection — alert when the 403 ratio
exceeds, say, 5% of total traffic in any single hour.

### 4. `04_requests_by_country`

**What it tells you:** request volume by viewer country, with a
`block_pct` column. Filters out countries with fewer than 100 requests
to suppress noise.

**When to use:** geographic anomaly detection. A country that *normally*
sees a 1% block rate suddenly hitting 60% is a strong signal of a
bot campaign localised there.

### 5. `05_captcha_pass_rate`

**What it tells you:** fraction of CAPTCHA / challenge attempts that
were successfully solved, grouped by URI prefix.

**When to use:** UX impact assessment — if the solve-rate on `/login`
drops below ~70%, real users are being friction-challenged and you may
need to relax the rule. Conversely, near-100% solve from a single IP
range is a tell-tale of CAPTCHA-bypass services.

### 6. `06_uri_attack_distribution`

**What it tells you:** which URI roots are receiving the most blocked
requests, with the firing rules listed and the count of distinct IPs
hitting each.

**When to use:** identify "noisy" endpoints that may need their own
rate-limit scope-down statement, or confirm an attack is concentrated
on a single endpoint vs. broad-spectrum.

### 7. `07_anomalous_user_agents`

**What it tells you:** user-agent prefixes (first 80 chars) with
abnormally high block percentages over a sliding 24-hour window. The
HAVING clause requires both volume (50+ requests) and block-rate
(>=10%) so legitimate UAs don't surface.

**When to use:** identifying low-quality scrapers and bot frameworks
that don't match Bot Control's signatures yet. Feed unique prefixes
into a custom WAF rule once confirmed.

### 8. `08_rate_limit_hits_per_path`

**What it tells you:** which URIs are tripping the rate-based rules,
with hit counts and unique-IP fan-out.

**When to use:** rate-limit threshold tuning. If `unique_ips` is small
relative to `hits`, a few clients are drowning the rule — bump the
per-IP limit or convert to per-IP-AND-URI scope. If `unique_ips` is
high, consider a global stricter limit.

---

## Ad-hoc forensic recipes

These are *not* provisioned as named queries — copy into the Athena
console and adjust the partition filters / SQL as needed.

### A. "Show me every BLOCK against IP `X` in the last 7 days"

```sql
SELECT
  from_unixtime(timestamp/1000)            AS ts_utc,
  action,
  terminatingruleid                        AS rule,
  httprequest.uri                          AS uri,
  httprequest.httpmethod                   AS method,
  httprequest.country                      AS country,
  responsecodesent                         AS status
FROM <db>.waf_logs
WHERE httprequest.clientip = '203.0.113.42'
  AND year = 2026
  AND month = 4
  AND day BETWEEN 22 AND 29
ORDER BY ts_utc DESC
LIMIT 1000;
```

### B. "What were Bot Control labels seeing on `/api`?"

```sql
SELECT
  l.name                                   AS bot_label,
  COUNT(*)                                 AS hits,
  COUNT(DISTINCT httprequest.clientip)     AS distinct_ips
FROM <db>.waf_logs
CROSS JOIN UNNEST(labels) AS t(l)
WHERE httprequest.uri LIKE '/api%'
  AND year = 2026 AND month = 5 AND day = 1
  AND l.name LIKE 'awswaf:managed:aws:bot-control%'
GROUP BY 1
ORDER BY hits DESC;
```

### C. "Per-minute rate of CAPTCHA / CHALLENGE in the last 24h"

```sql
SELECT
  date_trunc('minute', from_unixtime(timestamp/1000)) AS minute_utc,
  action,
  COUNT(*)                                            AS hits
FROM <db>.waf_logs
WHERE action IN ('CAPTCHA', 'CHALLENGE')
  AND year  = CAST(year(current_date) AS int)
  AND month = CAST(month(current_date) AS int)
  AND day BETWEEN CAST(day(current_date) - 1 AS int) AND CAST(day(current_date) AS int)
GROUP BY 1, 2
ORDER BY minute_utc;
```

### D. "Sample raw record for a specific request_id"

Useful when an SRE has a `x-amzn-requestid` header value from a customer
report and wants the full WAF context around the matching request.

```sql
SELECT *
FROM <db>.waf_logs
WHERE httprequest.requestid = 'abc123-def456-...'
  AND year = 2026 AND month = 4 AND day = 28
LIMIT 5;
```

### E. "5xx rate by ALB target group" (joins with ALB logs if present)

```sql
WITH waf AS (
  SELECT
    httprequest.requestid                            AS rid,
    responsecodesent                                 AS waf_status
  FROM <db>.waf_logs
  WHERE year = 2026 AND month = 4 AND day = 28
    AND responsecodesent >= 500
)
SELECT
  COUNT(*)         AS waf_5xx_count,
  MIN(waf_status)  AS min_status,
  MAX(waf_status)  AS max_status
FROM waf;
```

### F. "Top countries by CAPTCHA failure rate"

```sql
SELECT
  httprequest.country                                                  AS country,
  COUNT_IF(captcharesponse.responsecode = 0)                           AS solved,
  COUNT(*)                                                             AS attempts,
  ROUND(100.0 * COUNT_IF(captcharesponse.responsecode != 0) / COUNT(*), 2) AS fail_pct
FROM <db>.waf_logs
WHERE action = 'CAPTCHA'
  AND year = 2026 AND month = 4 AND day = 28
GROUP BY 1
HAVING COUNT(*) > 50
ORDER BY fail_pct DESC;
```

### G. "Average WAF inspection latency (header-inserted indicator)"

WAF doesn't emit explicit timing, but Lambda@Edge writes a correlation
header (`x-edge-rid`) we can filter on to see what fraction of requests
made it past the edge stack vs. were blocked at WAF.

```sql
SELECT
  CASE
    WHEN cardinality(filter(httprequest.headers, h -> lower(h.name) = 'x-edge-rid')) > 0
      THEN 'reached-edge-fn'
    ELSE 'blocked-at-waf-or-pre-edge'
  END                            AS stage,
  COUNT(*)                       AS request_count
FROM <db>.waf_logs
WHERE year = 2026 AND month = 4 AND day = 28
GROUP BY 1;
```

---

## Cost & performance tips

- **Always include partition filters** on `year`, `month`, `day` (and
  ideally `hour`). Athena charges per byte scanned; a single-day filter
  is 24x cheaper than a single-month filter.
- **Use `LIMIT`** during exploration. The full named queries cap their
  output already — adopt the same pattern in ad-hoc work.
- **Project only the columns you need.** WAF records are wide; selecting
  `*` is convenient but multiplies scan cost on pure-Parquet tables.
- **Set the workgroup before you query.** All saved queries belong to
  the `<prefix>-waf-logs` workgroup, which enforces the bytes-scanned
  cap and the SSE-KMS result encryption.

---

## Schema-drift response

If the Glue crawler reports a new top-level field (visible in CloudWatch
under `/aws-glue/crawlers/<name>`), follow this checklist:

1. Compare `glue:GetTable` `StorageDescriptor.Columns` against the
   committed schema in `terraform/modules/waf-logs/glue.tf`.
2. If a new field appears: add it to the explicit columns list, run
   `terraform plan` and review (the change should be additive only).
3. Apply via the standard CI pipeline.
4. Re-run the crawler to verify it no longer flags drift.

If the field type *changes* (very rare — AWS treats this as a breaking
change), contact AWS Support before mutating the table; coordination is
needed to avoid a Firehose delivery freeze during conversion.
