#!/bin/bash

export APP_NAME="rbac"  # name of app-sre "application" folder this component lives in
export COMPONENT_NAME="rbac"  # name of app-sre "resourceTemplate" in deploy.yaml for this component
export IMAGE="quay.io/cloudservices/rbac"  # the image location on quay

export IQE_PLUGINS="rbac"  # name of the IQE plugin for this APP
export IQE_MARKER_EXPRESSION="rbac_smoke"  # This is the value passed to pytest -m
export IQE_FILTER_EXPRESSION=""  # This is the value passed to pytest -k

find . -name cdappconfig.json

# Install bonfire repo/initialize
CICD_URL=https://raw.githubusercontent.com/RedHatInsights/bonfire/master/cicd
curl -s $CICD_URL/bootstrap.sh > .cicd_bootstrap.sh && source .cicd_bootstrap.sh

source $CICD_ROOT/build.sh
# Run unit tests
#source $APP_ROOT/unit_test.sh

# Deploy to eph
source $CICD_ROOT/deploy_ephemeral_env.sh

# Smoke tests
source $APP_ROOT/smoke_test.sh
