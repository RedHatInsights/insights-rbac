#!/bin/bash

set -ex
export CONTAINER_NAME="rbac-pr-check"
export IMAGE_TAG="rbac:pr-check"

function teardown_docker() {
    docker rm -f $CONTAINER_NAME || true
    docker image rm -f $IMAGE_TAG || true
}

# Catches process termination and cleans up Docker artifacts
trap "teardown_docker" EXIT SIGINT SIGTERM

set -ex 
# # Setup environment for pre-commit check
# python3.9 -m venv .
# source bin/activate
# bin/pip3 install pipenv
# bin/pip3 install black pre-commit

#Run pre-commit
# if ! (pre-commit run -a); then
#     echo "pre-commit ecountered an issue"
#     exit 1
# fi

# Build PR_CHECK Image
docker build -f './Dockerfile-pr-check' --label $CONTAINER_NAME --tag $IMAGE_TAG .

# Build PR_Check Container
docker create --name $CONTAINER_NAME $IMAGE_TAG tox


# Run PR_CHECK Container (attached with standard output)
# and reports if the Containerized PR_Check fails
if ! (docker start -a $CONTAINER_NAME); then
    echo "Test failure observed; aborting"
    exit 1
fi

# Pass Jenkins dummy artifacts as it needs
# an xml output to consider the job a success.
mkdir -p $WORKSPACE/artifacts
cat << EOF > $WORKSPACE/artifacts/junit-dummy.xml
<testsuite tests="1">
    <testcase classname="dummy" name="dummytest"/>
</testsuite>
EOF
 
