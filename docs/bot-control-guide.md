# Bot Control Guide

> AWSManagedRulesBotControlRuleSet: how this platform uses it, why the
> defaults are what they are, and how to tune it without surprising your
> users or your finance team.

## TL;DR

- We run **TARGETED** inspection scoped to **`/api/*`** with a
  `trusted_bot_ips` bypass for our own monitoring egress.
- "Definitely-bad" categories (e.g. signal `automated_browser`) are
  routed to **CAPTCHA**, not `block`, so legit-but-mislabeled traffic
  can resolve a challenge instead of failing silently.
- Search engine crawlers (Googlebot, Bingbot) are explicitly **allowed**
  so SEO does not regress.
- Default-allow records are dropped from logs (Day 35 — Athena indexing
  ignores them anyway), saving 80–95% of log volume on most workloads.

## Targeted vs Common — what's the difference?

AWS WAF Bot Control supports two inspection levels:

### COMMON (the cheaper baseline)

- Signature-based detection only.
- ~50 WCU per request that hits the rule.
- Catches obvious automation: `curl`, `wget`, `python-requests`, classic
  `User-Agent` strings, well-known scrapers, and clients that fail
  trivial header sanity checks.
- Misses sophisticated automation like headless Chrome, Puppeteer,
  Selenium with stealth plugins, and residential-proxy networks.
- Cost: standard WAF inspection charges only.

### TARGETED (the default in this module)

- COMMON + ML / behavioural heuristics.
- ~50 WCU per request **plus** Bot Control's per-request fee (currently
  $1.00 per 1M Bot Control requests on top of the standard
  $0.60 per 1M WAF requests — check the WAF pricing page for the
  current value).
- Catches automation frameworks, headless browsers, and clients that
  imitate browsers but fail behavioural checks (mouse signal absent,
  fingerprint anomalies, etc.).
- Adds the `signal:automated_browser` label that we route to CAPTCHA.
- Cost: noticeably more than COMMON. For a 100M-req/month app that's
  roughly $100/month extra **before** discounts — pay attention if you
  serve cheap static assets.

### When to pick which

- **TARGETED** for any workload exposed to credential stuffing,
  scraping of paid content, inventory hoarding, or content fraud — i.e.
  where a determined attacker would invest in better tooling.
- **COMMON** for read-only public sites that don't care about scraping
  and only want to filter out obvious bots cheaply.
- **Disabled** for pre-prod environments and dev sandboxes — set
  `bot_control_enabled = false`.

## Scope-down: only inspect `/api/*`

Inspecting every static-asset request with Bot Control is wasteful: most
abuse targets dynamic endpoints. The `bot_control_scope_down_path`
variable (default `/api`) constrains BotControl to paths starting with
that prefix, which typically reduces inspected request volume by
70–95% on a typical web app.

To inspect every request — for an API-only platform where nearly all
traffic is dynamic — set `bot_control_scope_down_path = "/"`.

The scope-down also has a `NOT IpSet(trusted_bots)` clause: trusted bot
CIDRs (your own monitoring, partner integrations, etc.) bypass Bot
Control entirely. Empty by default.

## Two-stage handling: label first, act later

Bot Control adds labels to requests it inspects:

- `awswaf:managed:aws:bot-control:bot:category:<category>` — bucketed
  category (e.g. `http_library`, `monitoring`, `search_engine`,
  `social_media`).
- `awswaf:managed:aws:bot-control:signal:<signal>` — heuristic signal
  (e.g. `automated_browser`, `non_browser`).
- `awswaf:managed:aws:bot-control:bot:name:<name>` — specific named bot
  when known (e.g. `googlebot`).

The Bot Control rule itself is configured to **count** (not block) for
several categories (`http_library`, `monitoring`, `search_engine`,
`automated_browser`). A second rule group, `BotLabelResponses`, runs
right after BotControl and inspects those labels:

| Label                                            | Action                |
|--------------------------------------------------|-----------------------|
| `signal:automated_browser`                       | CAPTCHA               |
| `bot:category:http_library`                      | CAPTCHA               |
| `bot:category:monitoring`                        | Silent challenge      |
| `bot:category:search_engine`                     | Allow (SEO-friendly)  |
| any other bot label not overridden               | (block — managed rule)|

This separation is the recommended Bot Control pattern: by the time a
label-based rule fires, you can change the response without re-deploying
the managed rule group. Tuning a label override is a 30-second policy
change.

## Path-based CAPTCHA / challenge

In addition to label-based responses, the module's custom rule group has
two path-based rules:

- **CaptchaOnAuthPaths** (priority 4): CAPTCHA on `/login` and `/signup`
  by default. CAPTCHA fights credential stuffing without hard-blocking
  legitimate users.
- **ChallengeOnCheckout** (priority 5): silent token challenge on
  `/checkout`. Real browsers carry the WAF token automatically; bots
  without a valid token are rejected. Critical for payment endpoints
  where a CAPTCHA would tank conversion.

Override the path lists with `var.captcha_paths` and
`var.challenge_paths`. Set either to `[]` to disable.

### Immunity time

Both rules set an immunity time so users aren't re-challenged constantly:

- CAPTCHA: 5 minutes (long enough for OTP entry, short enough that a
  solved token can't be replayed indefinitely).
- Challenge: 10 minutes (covers a typical 3DS-redirect checkout flow).

## Tuning strategies

### Phase 1 — observe (week 1)

Deploy with `rate_limit_action = "count"` (or set the BotControl rule
itself to override-count) and watch CloudWatch metrics for two days.
Look for:

- High BlockMissingUA counts that turn out to be a misbehaving SDK →
  whitelist the IP via `trusted_bot_ips`.
- High `category:http_library` counts on a known-good integration →
  add the partner CIDR to `trusted_bot_ips` instead of solving CAPTCHA.
- Search-engine traffic getting CAPTCHA → confirm the
  `AllowSearchEngines` rule is firing first (priority 4 in the bot
  label responder rule group).

### Phase 2 — enforce (week 2)

Flip `rate_limit_action = "block"`, keep BotControl in normal action
mode. Monitor real user complaints and the `BotControlBlocked` and
`BotControlCaptcha` metrics.

### Phase 3 — refine (ongoing)

- If false positives appear on `signal:automated_browser`, change the
  label-response rule from `captcha` to `count` and inspect the matched
  user agents in WAF sample logs (Day 35 / Athena queries).
- If CAPTCHA solve rate is below 60%, the CAPTCHA puzzle may be too
  hard — open an AWS support case to lower the difficulty.

## Cost watch-outs

- Bot Control charges per 1M requests **inspected**, not per 1M
  requests through CloudFront. The `/api/*` scope-down is your single
  biggest lever.
- CloudFront cache hits short-circuit the WAF entirely — make sure
  authenticated traffic is **uncached** (which is normal) but anything
  that *can* be cached is, so it never reaches the WAF in the first
  place.
- Targeted ML costs are roughly 2× the Common-level costs. Re-evaluate
  monthly: if your dynamic traffic is small (~10M req/mo), TARGETED
  costs cents and is worth keeping; at 1B req/mo you should price-model
  whether the marginal TARGETED catches justify the spend.
- The `BotLabelResponses` rule group adds ~25 WCU and is essentially
  free; don't disable it just to save WCU budget.

## Operational checklist

- [ ] Confirm CloudFront is configured with `web_acl_id` pointing at
  this web ACL ARN.
- [ ] Verify the WAF token JS is served on pages that lead to
  `/checkout` (silent challenge requires the token).
- [ ] Add the platform's monitoring egress CIDRs to `trusted_bot_ips`.
- [ ] Run the WAF logging Athena queries (Day 35) at least weekly to
  spot tuning opportunities.
- [ ] After 30 days, archive the BotControl CloudWatch metrics for
  trend analysis — you'll need the baseline for any future tuning.

## References

- [Bot Control rule list](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html)
- [Targeted protections](https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control-rg-targeted.html)
- [WAF labels](https://docs.aws.amazon.com/waf/latest/developerguide/waf-labels.html)
- [WAF pricing](https://aws.amazon.com/waf/pricing/) (Bot Control add-on row)
- [CAPTCHA & challenge actions](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge.html)
