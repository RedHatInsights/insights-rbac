#!/usr/bin/env bash
# Tear down the full local integration stack (HBI + Kessel/Debezium/RBAC).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=../common/logging.sh
source "${SCRIPT_DIR}/../common/logging.sh"
# shellcheck source=../common/container_runtime.sh
source "${SCRIPT_DIR}/../common/container_runtime.sh"

detect_container_runtime

INVENTORY_API_REPO="${INVENTORY_API_REPO:-${KESSEL_REPO:-}}"
HBI_REPO="${HBI_REPO:-}"
HBI_COMPOSE_PROJECT="${HBI_COMPOSE_PROJECT:-hbi-kessel-local}"
REMOVE_VOLUMES=false

usage() {
  cat <<'EOF'
Usage: down-full.sh [options]

  -v, --volumes   Remove compose volumes when stopping HBI
  -h, --help      Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v | --volumes) REMOVE_VOLUMES=true; shift ;;
    -h | --help) usage; exit 0 ;;
    *)
      log-err "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${INVENTORY_API_REPO}" || ! -f "${INVENTORY_API_REPO}/scripts/stop-full-kessel.sh" ]]; then
  INVENTORY_API_REPO="$(dirname "${REPO_ROOT}")/inventory-api"
fi
if [[ ! -f "${INVENTORY_API_REPO}/scripts/stop-full-kessel.sh" ]]; then
  INVENTORY_API_REPO="${REPO_ROOT}/.local-deps/inventory-api"
fi

if [[ -z "${HBI_REPO}" || ! -f "${HBI_REPO}/dev.yml" ]]; then
  HBI_REPO="$(dirname "${REPO_ROOT}")/insights-host-inventory"
fi
if [[ ! -f "${HBI_REPO}/dev.yml" ]]; then
  HBI_REPO="${REPO_ROOT}/.local-deps/insights-host-inventory"
fi

down_compose() {
  if [[ "${REMOVE_VOLUMES}" == true ]]; then
    "${COMPOSE_CMD[@]}" "$@" down -v
  else
    "${COMPOSE_CMD[@]}" "$@" down
  fi
}

if [[ -f "${HBI_REPO}/dev.yml" ]]; then
  log-info "Stopping Host Inventory (${HBI_COMPOSE_PROJECT})..."
  down_compose -p "${HBI_COMPOSE_PROJECT}" \
    -f "${HBI_REPO}/dev.yml" \
    -f "${REPO_ROOT}/scripts/local_stack/hbi.integration.yml" || log-warn "HBI dev.yml compose down failed (may not be running)"
else
  log-warn "HBI compose files not found; skipping HBI teardown"
fi

if [[ -f "${INVENTORY_API_REPO}/scripts/stop-full-kessel.sh" ]]; then
  log-info "Stopping Kessel + Debezium + RBAC..."
  (
    cd "${INVENTORY_API_REPO}"
    export DOCKER="${CONTAINER_RUNTIME}"
    ./scripts/stop-full-kessel.sh
  )
else
  log-warn "inventory-api repo not found; skipping Kessel stack teardown"
fi

log-info "Full local stack stopped."
