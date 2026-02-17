#!/usr/bin/env bash
set -eu -o pipefail

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

STATE_DIR="${EPHEMERAL_DIR}"/state
mkdir -p -- "$STATE_DIR"

REPO=$(echo "${EPHEMERAL_DIR}"| rev | cut -d/ -f3- | rev)
TEMPLATE_FILE="${EPHEMERAL_DIR}"/config_template.yaml
CONFIG_FILE="${STATE_DIR}"/config.yaml
TAG_FILE="${STATE_DIR}"/current-tag
APP_NAME=rbac
RBAC_FWD_PORT=9080

RBAC_CONFIG_REPO="RedHatInsights/rbac-config"

usage() {
  log-info "Usage: $(basename "$0") <command> [command_arg]"
  log-info ""
  log-info "commands:"
  log-info "\t build <tag>            build image (default tag: random UUID)"
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

  echo "$_tag" > "$TAG_FILE"
  update-config-file "${_tag}"
}

_fetch_rbac_config() {
  local commit="$1"
  local file="$2"

  curl -L --fail-with-body "https://raw.githubusercontent.com/$RBAC_CONFIG_REPO/$commit/$file"
}

# Given the JSON representation of a Kubernetes item, naively unwraps a provided parameterless Template into its
# component objects. This will fail if the template has parameters (since we cannot in general know how to handle
# those).
#
# The output format is a stream (not an array) of JSON objects (suitable for ingestion with jq).
_unwrapped_items_for() {
  local item="$1"

  if [[ "$(printf '%s' "$item" | jq -r .kind)" != "Template" ]]; then
    printf '%s\n' "$item"
    return
  fi

  if [[ "$(printf '%s' "$item" | jq '.parameters == null or .parameters == []')" != "true" ]]; then
    echo "Expected Template to have no parameters. (It cannot be generically unwrapped otherwise.)" >&2
    exit 1
  fi

  printf '%s' "$item" | jq '.objects[]'
}

# Outputs a stream of JSON objects to be used for updating the Kubernetes config that will be deployed.
_make_override_items() {
  if ! command -v yq > /dev/null; then
    echo "yq is required for this script." >&2
    echo "Consider installing it with \`uv tool install yq\`." >&2
    return 1
  fi

  local config_commit
  config_commit="$(git ls-remote -- "https://github.com/$RBAC_CONFIG_REPO" refs/heads/master | cut -f 1)"

  local raw_items=()

  # Here, we ensure that RBAC and Kessel are using the same version of rbac-config. I am not entirely sure why this is
  # necessary, since Kessel's ephemeral config does appear to use rbac-config master, but, before doing this, I was
  # getting issues with RBAC trying to add relations that Kessel didn't recognize.

  raw_items+=(
    "$(_fetch_rbac_config "$config_commit" "_private/configmaps/stage/rbac-config.yml" | yq)"
  )

  raw_items+=(
    "$(_fetch_rbac_config "$config_commit" "_private/configmaps/stage/model-access-permissions.configmap.yml" | yq)"
  )

  # This is based off of
  # https://gitlab.cee.redhat.com/service/app-interface/-/blob/34a588e5528c9c8710bb3159d27f915af323efcd/resources/insights-ephemeral/kessel/kessel-spicedb-schema-configmap.yml
  raw_items+=(
    "$(
      _fetch_rbac_config "$config_commit" "configs/stage/schemas/schema.zed" \
      | jq -Rs '{
        apiVersion: "v1",
        kind: "ConfigMap",
        data: {
          "schema.zed": .
        },
        metadata: {
          name: "spicedb-schema",
          annotations: {
            "qontract.recycle": "true"
          }
        }
      }'
    )"
  )

  for raw_map in "${raw_items[@]}"; do
    # The ConfigMaps in rbac-config are represented as parameterless templates, so we need to unwrap them.
    # This will write the output to our own stdout (since we just need to output the stream of all items to add).
    _unwrapped_items_for "$raw_map"
  done
}

deploy() {
  get-namespace

  log-info "deploying..."
  log-debug "bonfire process rbac \
  --source=appsre \
  --local-config-path ${CONFIG_FILE} \
  --no-remove-resources ${APP_NAME} \
  --namespace ${NAMESPACE} | oc apply -f - -n ${NAMESPACE}"

  if [[ -f "$TAG_FILE" ]]; then
    local _tag
    _tag="$(cat -- "$TAG_FILE")"
    update-config-file "${_tag}"
  fi

  if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Config file does not exist and could not be generated." >&2
    echo "You should run \`ephemeral.sh build\` before running \`ephemeral.sh deploy\`." >&2
    return 1
  fi

  local override_items_file
  override_items_file="$(mktemp)"

  _make_override_items > "$override_items_file"

  local override_item_kinds
  override_item_kinds="$(cat -- "$override_items_file" | jq -r '.kind' | sort | uniq)"

  if [[ "$override_item_kinds" != "ConfigMap" ]]; then
    echo "Expected only ConfigMaps, but found the following item kinds:" >&2
    printf '%s\n' "$override_item_kinds" >&2
    exit 1
  fi

  local override_item_names
  mapfile -t override_item_names < <(cat -- "$override_items_file" | jq -r '.metadata.name')

  bonfire process \
    rbac kessel \
    --source=appsre \
    --local-config-path "${CONFIG_FILE}" \
    --no-remove-resources "${APP_NAME}" \
    --namespace "${NAMESPACE}" \
  | jq \
      '. * {
        items: [
          .items[] | select(
            (
              (.kind == "ConfigMap") and
              (.metadata.name as $name | (($ARGS.named.overridden_names | index([$name])) != null))
            ) | not
          )
        ]
      }' \
      --argjson overridden_names "$(jq -n '$ARGS.positional' --args "${override_item_names[@]}")" \
  | jq \
      '. * {items: [.items[], $ARGS.named.new_items[]]}' \
      --slurpfile new_items "$override_items_file" \
  | oc apply -f - -n "${NAMESPACE}"
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
 "build") build "${2:-"$(uuidgen)"}";;
 "deploy") deploy;;
 "pods") pods;;
 "pf-rbac") port-forward-rbac "${2:-9080}";;
 "release") release;;
 "reserve") reserve "${2:-24h}";;
 "help") usage;;
 *) usage;;
esac
