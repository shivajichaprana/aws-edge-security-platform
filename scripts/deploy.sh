#!/usr/bin/env bash
# deploy.sh — terraform lifecycle wrapper for aws-edge-security-platform.
#
# Wraps `terraform init/plan/apply/destroy` with safety nets:
#  * pinned Terraform version check.
#  * workspace awareness.
#  * plan-then-apply flow (no `--auto-approve` shortcuts).
#  * coloured output.
#  * timing for each phase.
#
# Usage:
#   scripts/deploy.sh init     [--upgrade]
#   scripts/deploy.sh plan     [--var-file=path]
#   scripts/deploy.sh apply
#   scripts/deploy.sh destroy
#   scripts/deploy.sh output   [name]

set -euo pipefail
IFS=$'\n\t'

# ───── Configuration ─────
TF_DIR="${TF_DIR:-terraform}"
WORKSPACE="${WORKSPACE:-default}"
VAR_FILE="${VAR_FILE:-terraform.tfvars}"
PLAN_FILE="${PLAN_FILE:-edge.tfplan}"
TF_REQUIRED_MAJOR_MINOR="${TF_REQUIRED_MAJOR_MINOR:-1.7}"

# ───── Colours ─────
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
    GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"; RED="$(tput setaf 1)"; BOLD="$(tput bold)"; RESET="$(tput sgr0)"
else
    GREEN=""; YELLOW=""; RED=""; BOLD=""; RESET=""
fi

log()  { printf "%s>>%s %s\n" "${GREEN}" "${RESET}" "$*"; }
warn() { printf "%s!!%s %s\n" "${YELLOW}" "${RESET}" "$*" >&2; }
fail() { printf "%sxx%s %s\n" "${RED}" "${RESET}" "$*" >&2; exit 1; }

# ───── Helpers ─────
usage() {
    cat <<USAGE
${BOLD}deploy.sh${RESET} — terraform wrapper for aws-edge-security-platform

usage: scripts/deploy.sh <command> [args...]

commands:
  init        Run \`terraform init\` (use --upgrade to upgrade providers)
  plan        Run \`terraform plan -out=${PLAN_FILE}\`
  apply       Apply the saved plan (${PLAN_FILE})
  destroy     Plan + apply destroy (interactive confirmation required)
  output      Print terraform outputs (optional output name)
  workspace   Switch to / create workspace ${WORKSPACE}
  help        Show this message

env vars:
  TF_DIR=${TF_DIR}
  WORKSPACE=${WORKSPACE}
  VAR_FILE=${VAR_FILE}
  PLAN_FILE=${PLAN_FILE}
USAGE
}

ensure_tools() {
    command -v terraform >/dev/null 2>&1 || fail "terraform not installed"
    local version
    version="$(terraform version -json | python3 -c 'import json,sys; print(json.load(sys.stdin)["terraform_version"])' 2>/dev/null || terraform -version | head -n1 | awk '{print $2}' | tr -d 'v')"
    case "${version}" in
        ${TF_REQUIRED_MAJOR_MINOR}.*) : ;;
        *) warn "Terraform version ${version} differs from expected ${TF_REQUIRED_MAJOR_MINOR}.x — proceeding" ;;
    esac
}

ensure_var_file() {
    if [[ ! -f "${TF_DIR}/${VAR_FILE}" ]]; then
        if [[ -f "${TF_DIR}/${VAR_FILE}.example" ]]; then
            warn "${TF_DIR}/${VAR_FILE} missing; copy ${VAR_FILE}.example and customise"
        else
            warn "${TF_DIR}/${VAR_FILE} missing; using defaults from variables.tf"
        fi
    fi
}

select_workspace() {
    pushd "${TF_DIR}" >/dev/null
    if ! terraform workspace select "${WORKSPACE}" >/dev/null 2>&1; then
        log "creating workspace ${WORKSPACE}"
        terraform workspace new "${WORKSPACE}"
    fi
    popd >/dev/null
}

# ───── Commands ─────
cmd_init() {
    ensure_tools
    log "terraform init in ${TF_DIR}"
    pushd "${TF_DIR}" >/dev/null
    if [[ "${1:-}" == "--upgrade" ]]; then
        terraform init -upgrade -input=false
    else
        terraform init -input=false
    fi
    popd >/dev/null
}

cmd_plan() {
    ensure_tools
    ensure_var_file
    select_workspace
    log "terraform plan -> ${PLAN_FILE}"
    pushd "${TF_DIR}" >/dev/null
    local args=(-input=false -out="${PLAN_FILE}" -compact-warnings)
    [[ -f "${VAR_FILE}" ]] && args+=(-var-file="${VAR_FILE}")
    terraform plan "${args[@]}"
    popd >/dev/null
}

cmd_apply() {
    ensure_tools
    select_workspace
    pushd "${TF_DIR}" >/dev/null
    if [[ ! -f "${PLAN_FILE}" ]]; then
        fail "${PLAN_FILE} not found — run 'plan' first"
    fi
    log "terraform apply ${PLAN_FILE}"
    terraform apply -input=false "${PLAN_FILE}"
    rm -f "${PLAN_FILE}"
    popd >/dev/null
}

cmd_destroy() {
    ensure_tools
    select_workspace
    pushd "${TF_DIR}" >/dev/null
    warn "About to destroy all resources in workspace=${WORKSPACE}"
    read -r -p "Type 'destroy' to confirm: " confirm
    [[ "${confirm}" == "destroy" ]] || fail "Aborted"
    local args=(-input=false -auto-approve)
    [[ -f "${VAR_FILE}" ]] && args+=(-var-file="${VAR_FILE}")
    terraform destroy "${args[@]}"
    popd >/dev/null
}

cmd_output() {
    ensure_tools
    pushd "${TF_DIR}" >/dev/null
    if [[ $# -gt 0 ]]; then
        terraform output -raw "$1"
    else
        terraform output
    fi
    popd >/dev/null
}

cmd_workspace() {
    ensure_tools
    select_workspace
    log "active workspace: ${WORKSPACE}"
}

# ───── Entry point ─────
main() {
    local cmd="${1:-help}"
    shift || true
    local start_ts end_ts
    start_ts="$(date +%s)"

    case "${cmd}" in
        init)       cmd_init "$@" ;;
        plan)       cmd_plan "$@" ;;
        apply)      cmd_apply "$@" ;;
        destroy)    cmd_destroy "$@" ;;
        output)     cmd_output "$@" ;;
        workspace)  cmd_workspace "$@" ;;
        help|-h|--help) usage; exit 0 ;;
        *) usage; fail "unknown command: ${cmd}" ;;
    esac

    end_ts="$(date +%s)"
    log "${cmd} completed in $((end_ts - start_ts))s"
}

main "$@"
