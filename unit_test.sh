source ${CICD_ROOT}/_common_deploy_logic.sh

NAMESPACE=$(bonfire namespace reserve)

set -x
bonfire process \
    $APP_NAME \
    --source=appsre \
    --ref-env ${REF_ENV} \
    --set-template-ref ${COMPONENT_NAME}=${GIT_COMMIT} \
    --set-image-tag $IMAGE=$IMAGE_TAG \
    --namespace $NAMESPACE \
    $COMPONENTS_ARG \
    $COMPONENTS_RESOURCES_ARG | oc_wrapper apply -f - -n $NAMESPACE

bonfire namespace wait-on-resources $NAMESPACE 

local _service_name=${1}
local _local_port=${2}
local _service_port=${3}

log-info "oc port-forward service/${_service_name} ${_local_port}:${_service_port}"
  oc port-forward service/"${_service_name}" "${_local_port}":"${_service_port}"

local _port=${1:-RBAC_FWD_PORT}
port-forward rbac "${_port}" 8080

log-info "oc get pods -l app=${APP_NAME}"
oc get pods -l app="${APP_NAME}"

python3 --version 
python3.9 -m venv app-venv
source app-venv/bin/activate
pip install --upgrade pip setuptools wheel pipenv tox 
tox -r
result=$?
source .bonfire_venv/bin/activate



# TODO: add unittest-xml-reporting to rbac so that junit results can be parsed by jenkins
mkdir -p $WORKSPACE/artifacts
cat << EOF > $WORKSPACE/artifacts/junit-dummy.xml
<testsuite tests="1">
    <testcase classname="dummy" name="dummytest"/>
</testsuite>
EOF

if [ $result -ne 0 ]; then
  echo '====================================='
  echo '====  ✖ ERROR: UNIT TEST FAILED  ===='
  echo '====================================='
  exit 1
fi




