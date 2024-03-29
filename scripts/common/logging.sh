#!/usr/bin/env bash

# timestamp
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

if which tput &> /dev/null; then
  # colors
  ERR=$(tput setaf 1)
  INFO=$(tput setaf 178)
  WARN=$(tput setaf 165)
  TRACE=$(tput setaf 27)
  TS=$(tput setaf 2)
  TAG=$(tput setaf 10)
  RESET=$(tput sgr0)

  log(){
    local _tag_name=${1}
    local _msg=${@:2}

    printf "${TS}${TIMESTAMP} ${TAG}[${_tag_name}\t] ${_msg}\n"
    printf  ${RESET}
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
    local _debug=$(tr '[:upper:]' '[:lower:]' <<<"$DEBUG")
    if [[ ! -z "${DEBUG}" && ${_debug} == true ]];then
        log "DEBUG" "${TRACE} $@"
    fi
  }

else
  log(){
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
    local _debug=$(tr '[:upper:]' '[:lower:]' <<<"$DEBUG")
    if [[ ! -z "${DEBUG}" && ${_debug} == true ]];then
        log "DEBUG" "$@"
    fi
  }

  log-err() {
    log "ERROR" "$@"
  }
fi
