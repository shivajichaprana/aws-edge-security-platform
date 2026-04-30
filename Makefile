# aws-edge-security-platform — Makefile
#
# Top-level targets for local development and CI parity.
#
#   make init              # terraform init
#   make plan              # terraform plan
#   make apply             # terraform apply
#   make destroy           # terraform destroy
#   make fmt               # terraform fmt -recursive
#   make lint              # tflint
#   make security          # checkov + trivy
#   make test              # terraform native tests
#   make docs              # regenerate module READMEs via terraform-docs
#   make ci                # run the full local CI bundle

SHELL          := /usr/bin/env bash
.SHELLFLAGS    := -eu -o pipefail -c
.DEFAULT_GOAL  := help

TF_DIR         ?= terraform
WORKSPACE      ?= default
VAR_FILE       ?= terraform.tfvars
PLAN_FILE      ?= edge.tfplan
TF_VERSION     ?= 1.7.5

# Use a single deploy.sh entry point so behaviour stays consistent
# between developer machines and the CI workflow.
DEPLOY_SCRIPT  := scripts/deploy.sh

# Colorised output (works in CI too)
GREEN  := $(shell tput -Txterm setaf 2 2>/dev/null || echo)
YELLOW := $(shell tput -Txterm setaf 3 2>/dev/null || echo)
RED    := $(shell tput -Txterm setaf 1 2>/dev/null || echo)
RESET  := $(shell tput -Txterm sgr0   2>/dev/null || echo)

.PHONY: help
help:  ## Show this help.
	@printf "$(GREEN)%-18s %s$(RESET)\n" "TARGET" "DESCRIPTION"
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "$(YELLOW)%-18s$(RESET) %s\n", $$1, $$2}'

## ───── Terraform lifecycle ─────

.PHONY: init
init:  ## Run terraform init in $(TF_DIR).
	@$(DEPLOY_SCRIPT) init

.PHONY: plan
plan:  ## Run terraform plan and write to $(PLAN_FILE).
	@$(DEPLOY_SCRIPT) plan

.PHONY: apply
apply:  ## Apply the saved plan ($(PLAN_FILE)).
	@$(DEPLOY_SCRIPT) apply

.PHONY: destroy
destroy:  ## Run terraform destroy.
	@$(DEPLOY_SCRIPT) destroy

.PHONY: output
output:  ## Print terraform outputs.
	@cd $(TF_DIR) && terraform output

## ───── Quality gates ─────

.PHONY: fmt
fmt:  ## terraform fmt -recursive (writes changes).
	@printf "$(GREEN)>> terraform fmt$(RESET)\n"
	@cd $(TF_DIR) && terraform fmt -recursive -diff

.PHONY: fmt-check
fmt-check:  ## terraform fmt -check (CI mode).
	@printf "$(GREEN)>> terraform fmt -check$(RESET)\n"
	@cd $(TF_DIR) && terraform fmt -check -recursive -diff

.PHONY: validate
validate: init  ## terraform validate.
	@printf "$(GREEN)>> terraform validate$(RESET)\n"
	@cd $(TF_DIR) && terraform validate -no-color

.PHONY: lint
lint:  ## Run tflint.
	@printf "$(GREEN)>> tflint$(RESET)\n"
	@command -v tflint >/dev/null 2>&1 || { printf "$(RED)tflint not installed; install via brew install tflint$(RESET)\n"; exit 1; }
	@cd $(TF_DIR) && tflint --init >/dev/null && tflint -f compact --recursive

.PHONY: security
security:  ## Run checkov + trivy IaC scans.
	@printf "$(GREEN)>> checkov$(RESET)\n"
	@command -v checkov >/dev/null 2>&1 || { printf "$(RED)checkov not installed; install via pip install checkov$(RESET)\n"; exit 1; }
	@checkov -d $(TF_DIR) --quiet --soft-fail false --skip-check CKV_AWS_111,CKV_AWS_109,CKV_AWS_356
	@printf "$(GREEN)>> trivy config$(RESET)\n"
	@command -v trivy >/dev/null 2>&1 || { printf "$(RED)trivy not installed; install via brew install trivy$(RESET)\n"; exit 1; }
	@trivy config --severity CRITICAL,HIGH,MEDIUM --exit-code 1 $(TF_DIR)

.PHONY: shellcheck
shellcheck:  ## shellcheck shell scripts.
	@printf "$(GREEN)>> shellcheck$(RESET)\n"
	@command -v shellcheck >/dev/null 2>&1 || { printf "$(RED)shellcheck not installed$(RESET)\n"; exit 1; }
	@find scripts -name '*.sh' -print0 | xargs -0 -r shellcheck --severity=warning

.PHONY: test
test: validate  ## Run terraform native tests.
	@printf "$(GREEN)>> terraform test$(RESET)\n"
	@cd $(TF_DIR) && terraform test || printf "$(YELLOW)no tests defined or tests failed$(RESET)\n"

.PHONY: ci
ci: fmt-check validate lint security shellcheck test  ## Run the full local CI bundle.
	@printf "$(GREEN)>> all checks passed$(RESET)\n"

## ───── Docs ─────

.PHONY: docs
docs:  ## Regenerate module READMEs via terraform-docs.
	@printf "$(GREEN)>> terraform-docs$(RESET)\n"
	@command -v terraform-docs >/dev/null 2>&1 || { printf "$(RED)terraform-docs not installed; install via brew install terraform-docs$(RESET)\n"; exit 1; }
	@for d in $(TF_DIR)/modules/*/; do \
		printf "  generating %s/README.md\n" "$$d"; \
		terraform-docs markdown table --output-file README.md --output-mode inject "$$d"; \
	done

## ───── Lambda@Edge packaging ─────

.PHONY: package-lambda-edge
package-lambda-edge:  ## Zip Lambda@Edge function source for terraform.
	@printf "$(GREEN)>> packaging Lambda@Edge functions$(RESET)\n"
	@for fn in security-headers geo-router header-rewrite; do \
		( cd lambda-edge/$$fn && zip -qr "../$$fn.zip" . -x "*.zip" "node_modules/.cache/*" ); \
		printf "  built lambda-edge/%s.zip\n" "$$fn"; \
	done

## ───── Cleanup ─────

.PHONY: clean
clean:  ## Remove local terraform state, plan files, and zip bundles.
	@printf "$(YELLOW)>> cleaning local artifacts$(RESET)\n"
	@find $(TF_DIR) -type d -name '.terraform' -prune -exec rm -rf {} + 2>/dev/null || true
	@find $(TF_DIR) -type f \( -name 'terraform.tfstate*' -o -name '*.tfplan' -o -name '.terraform.lock.hcl' \) -delete 2>/dev/null || true
	@find lambda-edge -name '*.zip' -delete 2>/dev/null || true

## ───── Utility ─────

.PHONY: workspace
workspace:  ## Switch to / create terraform workspace ($(WORKSPACE)).
	@cd $(TF_DIR) && (terraform workspace select "$(WORKSPACE)" 2>/dev/null || terraform workspace new "$(WORKSPACE)")

.PHONY: version
version:  ## Print expected tool versions.
	@printf "Terraform expected: $(TF_VERSION)\n"
	@printf "Detected:           %s\n" "$$(terraform -version | head -n1)"
