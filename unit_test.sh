python3 -m venv app-venv
. app-venv/bin/activate
pip install --upgrade pip setuptools wheel pipenv tox psycopg2-binary
tox -r
result=$?

# TODO: add unittest-xml-reporting to rbac so that junit results can be parsed by jenkins
mkdir -p $WORKSPACE/artifacts
cat << EOF > $WORKSPACE/artifacts/junit-dummy.xml
<testsuite tests="1">
    <testcase classname="dummy" name="dummytest"/>
</testsuite>
EOF
