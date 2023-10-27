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




