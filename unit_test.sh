#what we need to do here is try to connect to the ephemeral env that we created
#so that we can run the unit tests and the smoke tests 

docker logs 

printenv 

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




