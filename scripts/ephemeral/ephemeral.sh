#!/usr/bin/env bash

EPHEMERAL_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
CMD=${1:-help}

export DEBUG=${DEBUG:-false}

# import common & logging
source "${EPHEMERAL_DIR}"/../common/logging.sh

trap handle_errors ERR

handle_errors() {
  log-err "An error occurred on or around line ${BASH_LINENO[0]}. Unable to continue."
  exit 1
}

if [[ -z "${QUAY_USER}" ]]; then
  log-err "QUAY_USER is not set in your environment"
  log-err "exiting..."
  exit 1
fi

if [[ -z "${EPHEMERAL_USER}" ]]; then
  log-err "EPHEMERAL_USER is not set in your environment"
  log-err "exiting..."
  exit 1
fi

REPO=$(echo "${EPHEMERAL_DIR}"| rev | cut -d/ -f3- | rev)
TEMPLATE_FILE="${EPHEMERAL_DIR}"/config_template.yaml
CONFIG_FILE="${EPHEMERAL_DIR}"/config.yaml
APP_NAME=rbac
RBAC_FWD_PORT=9080


usage() {
  log-info "Usage: $(basename "$0") <command> [command_arg]"
  log-info ""
  log-info "commands:"
  log-info "\t build <tag>            build image (default tag: 'latest')"
  log-info "\t deploy                 deploy app"
  log-info "\t help                   show usage"
  log-info "\t pods                   list all pods in your namespace"
  log-info "\t pf-rbac <port>         port forward RBAC service to local host (default local port: 9080)"
  log-info "\t release                release currently reserved namespace(default), or specify the namespace to release"
  log-info "\t reserve <hours>        reserve an ephemeral namespace for specified time (default hours: 24h)"
}

help() {
  usage
}

get-namespace() {
  export NAMESPACE=$(bonfire namespace list |grep "${EPHEMERAL_USER}" |awk '{print $1}')

  if [[ -z "${NAMESPACE}" ]]; then
    log-err "You have no current Name space"
    log-err "exiting..."
  exit 1
  fi

  oc project "${NAMESPACE}"
  log-info "NAMESPACE=${NAMESPACE}"
}

update-config-file() {
  local _tag=${1:-'latest'}

  log-info "Updated: ${CONFIG_FILE}"
  log-info "\tIMAGE: quay.io/${QUAY_USER}/insights-rbac"
  log-info "\tIMAGE_TAG: ${_tag}"
  log-info "\tREPO: ${REPO}"

  sed \
      -e s#%REPO%#"${REPO}"# \
     -e s#%IMAGE%#"quay.io/${QUAY_USER}/insights-rbac"# \
     -e s#%IMAGE_TAG%#"${_tag}"# "${TEMPLATE_FILE}" > "${CONFIG_FILE}"
}

reserve() {
  local _duration=${1:-24h}

  log-info "reserving..."
  log-info "bonfire namespace reserve -d ${_duration}"
  bonfire namespace reserve -d "${_duration}"
  get-namespace
}

release() {
  get-namespace
  log-info "releasing..."
  log-info "bonfire namespace release ${NAMESPACE}"
  bonfire namespace release "${NAMESPACE}"
  unset NAMESPACE
}

pods() {
  log-info "oc get pods -l app=${APP_NAME}"
  oc get pods -l app="${APP_NAME}"
}

build() {
  local _tag=${1:-'latest'}
  local _repo=quay.io/"${QUAY_USER}"/insights-rbac:"${_tag}"

  log-debug "docker build . --platform linux/amd64 -t ${_repo}"
  docker build . --platform linux/amd64 -t "${_repo}"

  log-debug "docker push ${_repo}"
  docker push "${_repo}"

  update-config-file "${_tag}"
}

deploy() {
  get-namespace

  log-info "deploying..."
  log-debug "bonfire process rbac \
  --source=appsre \
  --local-config-path ${CONFIG_FILE} \
  --no-remove-resources ${APP_NAME} \
  --namespace ${NAMESPACE} | oc apply -f - -n ${NAMESPACE}"

  bonfire process rbac \
  --source=appsre \
  --local-config-path "${CONFIG_FILE}" \
  --no-remove-resources "${APP_NAME}" \
  --namespace "${NAMESPACE}" | oc apply -f - -n "${NAMESPACE}"
}

port-forward() {
  local _service_name=${1}
  local _local_port=${2}
  local _service_port=${3}

  log-info "oc port-forward service/${_service_name} ${_local_port}:${_service_port}"
    oc port-forward service/"${_service_name}" "${_local_port}":"${_service_port}"
}

port-forward-rbac() {
  local _port=${1:-RBAC_FWD_PORT}
  port-forward rbac "${_port}" 8080
}

#
# execute
#
CMD=$(echo "${CMD}" | tr '[:upper:]' '[:lower:]')
case ${CMD} in
 "build") build "${2:-latest}";;
 "deploy") deploy;;
 "pods") pods;;
 "pf-rbac") port-forward-rbac "${2:-9080}";;
 "release") release;;
 "reserve") reserve "${2:-24h}";;
 "help") usage;;
 *) usage;;
esac
