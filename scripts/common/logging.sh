#!/usr/bin/env bash

# timestamp
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

_USE_COLORS=false
if command -v tput &>/dev/null && [ -n "${TERM:-}" ]; then
  # tput can fail in non-TTY environments; never abort callers using set -e
  if ERR=$(tput setaf 1 2>/dev/null) && INFO=$(tput setaf 3 2>/dev/null) && WARN=$(tput setaf 5 2>/dev/null) \
    && TRACE=$(tput setaf 6 2>/dev/null) && TS=$(tput setaf 2 2>/dev/null) && TAG=$(tput setaf 10 2>/dev/null) \
    && RESET=$(tput sgr0 2>/dev/null); then
    _USE_COLORS=true
  fi
fi

if [ "${_USE_COLORS}" = true ]; then
  log() {
    local _tag_name=${1}
    local _msg=${@:2}

    # shellcheck disable=SC2059
    printf "${TS}${TIMESTAMP} ${TAG}[${_tag_name}\t] ${_msg}\n"
    printf "%b" "${RESET}"
  }

  log-info() {
    log "INFO" "${INFO} $@"
  }

  log-warn() {
    log "WARNING" "${WARN} $@"
  }

  log-err() {
    log "ERROR" "${ERR} $@"
  }

  log-debug() {
    local _debug
    _debug=$(tr '[:upper:]' '[:lower:]' <<<"${DEBUG:-}")
    if [[ -n "${DEBUG:-}" && ${_debug} == true ]]; then
      log "DEBUG" "${TRACE} $@"
    fi
  }

else
  log() {
    local _tag_name=${1}
    local _msg=${@:2}

    printf "${TIMESTAMP} [${_tag_name}\t] ${_msg}\n"
  }

  log-info() {
    log "INFO" "$@"
  }

  log-warn() {
    log "WARNING" "$@"
  }

  log-debug() {
    local _debug
    _debug=$(tr '[:upper:]' '[:lower:]' <<<"${DEBUG:-}")
    if [[ -n "${DEBUG:-}" && ${_debug} == true ]]; then
      log "DEBUG" "$@"
    fi
  }

  log-err() {
    log "ERROR" "$@"
  }
fi
