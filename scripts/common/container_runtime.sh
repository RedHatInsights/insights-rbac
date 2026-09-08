#!/usr/bin/env bash
# Detect docker or podman and export COMPOSE_CMD, CONTAINER_RUNTIME, and DOCKER.
#
# Usage:
#   source scripts/common/container_runtime.sh
#   detect_container_runtime

detect_container_runtime() {
  if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    CONTAINER_RUNTIME="docker"
    DOCKER="docker"
    if docker compose version &>/dev/null 2>&1; then
      COMPOSE_CMD=(docker compose)
    elif command -v docker-compose &>/dev/null; then
      COMPOSE_CMD=(docker-compose)
    else
      log-err "docker compose not found. Install Docker Compose v2 or docker-compose."
      exit 1
    fi
  elif command -v podman &>/dev/null && podman info &>/dev/null 2>&1; then
    CONTAINER_RUNTIME="podman"
    DOCKER="podman"
    if podman compose version &>/dev/null 2>&1; then
      COMPOSE_CMD=(podman compose)
    else
      log-err "podman compose not found. Enable compose support in Podman."
      exit 1
    fi
  else
    log-err "Docker or Podman is not running. Start Docker Desktop or podman machine."
    exit 1
  fi

  export CONTAINER_RUNTIME DOCKER COMPOSE_CMD
  log-info "Using ${CONTAINER_RUNTIME} (${COMPOSE_CMD[*]})"
}
