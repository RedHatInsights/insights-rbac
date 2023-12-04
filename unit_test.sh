#!/bin/bash

set -ex
export CONTAINER_NAME="rbac-pr-check"
export IMAGE_TAG="rbac:pr-check"

# spin up the db for integration tests
DB_CONTAINER="rbac-$(uuidgen)"
echo "Spinning up container: ${DB_CONTAINER}"

docker run -d \
    --name $DB_CONTAINER \
    -p 5432 \
    -e POSTGRESQL_USER=root \
    -e POSTGRESQL_PASSWORD=root \
    -e POSTGRESQL_DATABASE=rbac \
    quay.io/cloudservices/postgresql-rds:14-1

PORT=$(docker inspect $DB_CONTAINER | grep HostPort | sort | uniq | grep -o [0-9]*)
echo "DB Listening on Port: ${PORT}"

export DATABASE_HOST=localhost
export DATABASE_PORT=$PORT
export DATABASE_USER=root
export DATABASE_PASSWORD=root
export DATABASE_NAME=rbac

echo "Running tests...here we go"

# Build PR_CHECK Image
docker build -f './Dockerfile-pr-check' --label $CONTAINER_NAME --tag $IMAGE_TAG .

# Build PR_Check Container
docker run -i --rm --name $CONTAINER_NAME \
    -e DATABASE_NAME=$DATABASE_NAME \
    -e DATABASE_HOST=$DATABASE_HOST \
    -e DATABASE_PORT=$DATABASE_PORT \
    -e DATABASE_USER=$DATABASE_USER \
    -e DATABASE_PASSWORD=$DATABASE_PASSWORD \
    --net=host \
    $IMAGE_TAG tox

OUT_CODE=$?

echo "Killing DB Container..."
docker kill $DB_CONTAINER
echo "Removing DB Container..."
docker rm -f $DB_CONTAINER


if [[ $OUT_CODE != 0 ]]; then
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
