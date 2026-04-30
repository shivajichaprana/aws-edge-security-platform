# Contributing

Thank you for considering a contribution to `aws-edge-security-platform`. This document describes the workflow, the bar we hold for merges, and the local checks you should run before opening a PR.

## Code of conduct

Be kind. Be technical. Critique code, not people. Keep discussion on the design, the security model, and the operational impact.

## Development environment

You will need:

- Terraform `>= 1.5`
- AWS CLI `>= 2.13`
- `tflint >= 0.50`
- `checkov >= 3.2`
- `trivy >= 0.49`
- `shellcheck`
- A Bash 4+ shell (macOS users: `brew install bash`)

Optional:
- `terraform-docs` for auto-generating module READMEs.
- `aws-vault` or `awsume` for credential management.

## Workflow

1. **Open an issue first** for non-trivial changes. New WAF rule groups, Lambda@Edge functions, or third-party dependencies need design review before implementation.
2. **Branch from `main`**: `git checkout -b feat/short-description`.
3. **Keep commits small and conventional**. Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(waf): ...`, `fix(cloudfront): ...`, `docs(runbook): ...`. One logical change per commit.
4. **Run local checks** (see below).
5. **Open a PR** with:
   - A summary of the problem and the chosen solution.
   - Trade-offs you considered.
   - Manual test results (e.g. `terraform plan` output, before/after curl results).
   - Cost-impact estimate if introducing new resources.

## Local checks

Run these before pushing — CI will run the same set:

```bash
make fmt          # terraform fmt -recursive
make lint         # tflint --recursive
make security     # checkov + trivy
make test         # terraform test (terraform/tests/)
make plan         # terraform plan against your sandbox account
```

A single combined check:

```bash
make ci
```

## Style guidelines

### Terraform

- One resource per file when the file gets >150 lines.
- `main.tf` for primary resources, `variables.tf` for inputs, `outputs.tf` for outputs, `versions.tf` for required-providers, `data.tf` for data sources.
- Variable names in `snake_case`, no Hungarian prefixes.
- Every variable must have `description` and `type`. Use `validation` blocks for non-trivial constraints (e.g. allowed values, regex).
- `locals { ... }` for derived values; do not compute the same expression in multiple places.
- Tag everything via the provider-level `default_tags` block.

### Shell scripts

- `#!/usr/bin/env bash` shebang.
- `set -euo pipefail` at the top, plus `IFS=$'\n\t'`.
- A `usage()` function and `--help` flag.
- Use `printf` over `echo -e`.
- Quote all variable expansions: `"$VAR"`, not `$VAR`.
- Trap signals for cleanup if you create temp files.

### Lambda@Edge / CloudFront Functions

- Lambda@Edge: Node.js LTS, no third-party deps where possible (cold-start matters), explicit `'use strict'`.
- CloudFront Functions: ES 5.1 only, no `async`, no `Promise`, no `let` for loop counters in older runtimes (mitigated in `cloudfront-js@2.0`).

### Documentation

- Every public-facing module gets a `README.md` with: purpose, inputs, outputs, examples, gotchas.
- Architecture decisions go in `docs/architecture.md` as ADRs.
- Operational runbooks live in `docs/runbook.md`. Keep them imperative ("Run X. If Y, run Z.").

## Security

- **No secrets in commits.** Use AWS Secrets Manager or SSM Parameter Store at runtime.
- **No `*` IAM principals** without explicit justification.
- **No `0.0.0.0/0` security-group ingress** outside CloudFront's documented ranges.
- **Pin GitHub Actions to commit SHAs**, not floating tags.
- **Pin Terraform module versions** when adding any external module.

## PR review

- A passing CI run is necessary, not sufficient.
- Two reviewer sign-offs for changes to `terraform/modules/waf/` or anything touching IAM.
- One reviewer for docs-only changes.
- Reviewers should run `terraform plan` themselves on a sandbox account for any change touching the cloudfront or waf modules.

## Releasing

The maintainers tag `vMAJOR.MINOR.PATCH` releases. Patch versions for documentation and CI; minor versions for new modules / new optional features; major versions for breaking variable or output changes.

## Questions?

Open a Discussion in the repo, or ping `@shivajichaprana` on the PR.
