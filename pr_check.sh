#!/bin/bash

APP_NAME="rbac"  # name of app-sre "application" folder this component lives in
COMPONENT_NAME="rbac"  # name of app-sre "resourceTemplate" in deploy.yaml for this component
IMAGE="quay.io/cloudservices/rbac"  # the image location on quay

IQE_PLUGINS="rbac"  # name of the IQE plugin for this APP
IQE_MARKER_EXPRESSION="rbac_smoke"  # This is the value passed to pytest -m
IQE_FILTER_EXPRESSION=""  # This is the value passed to pytest -k

# Install bonfire repo/initialize
CICD_URL=https://raw.githubusercontent.com/RedHatInsights/bonfire/master/cicd
curl -s $CICD_URL/bootstrap.sh > .cicd_bootstrap.sh && source .cicd_bootstrap.sh

source $CICD_ROOT/build.sh

source $APP_ROOT/unit_test.sh

