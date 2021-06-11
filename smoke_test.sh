# Spin up iqe pod and execute IQE tests in it

# Env vars defined by caller:
#IQE_PLUGINS="plugin1,plugin2" -- pytest plugins to run separated by ","
#IQE_MARKER_EXPRESSION="mymarker" -- pytest marker expression
#IQE_FILTER_EXPRESSION="something AND something_else" -- pytest filter, can be "" if no filter desired
#NAMESPACE="mynamespace" -- namespace to deploy iqe pod into, can be set by 'deploy_ephemeral_env.sh'

#IQE_POD_NAME="iqe-tests"

# create a custom svc acct for the iqe pod to run with that has elevated permissions
# SA=$(oc get -n $NAMESPACE sa iqe --ignore-not-found -o jsonpath='{.metadata.name}')
# if [ -z "$SA" ]; then
#     oc create -n $NAMESPACE sa iqe
# fi
# oc policy -n $NAMESPACE add-role-to-user edit system:serviceaccount:$NAMESPACE:iqe
# oc secrets -n $NAMESPACE link iqe quay-cloudservices-pull --for=pull,mount
oc apply -f $APP_ROOT/deploy/rbac-cji-smoketest.yml
sleep 30
oc logs -n $NAMESPACE job/rbac-smoke-tests-iqe -f &
oc wait --for=condition=Complete job/rbac-smoke-tests-iqe || oc wait --for=condition=Failed job/rbac-smoke-tests-iqe 

LAST=$(oc get pod -n $NAMESPACE -l=clowdjob=rbac-smoke-tests -o json | jq '[.items[].metadata.name] | last')
oc cp -n $NAMESPACE $LAST:artifacts/ $WORKSPACE/artifacts

#echo "copied artifacts from iqe pod: "
#ls -l $WORKSPACE/artifacts
