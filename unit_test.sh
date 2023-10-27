#create my own new ephemeral database
#and then we can try to connect to it 
# and try to run the unit tets

source $CICD_ROOT/deploy_ephemeral_db.sh

export PGPASSWORD=$DATABASE_ADMIN_PASSWORD

source .bonfire_venv/bin/activate
sudo yum install python3.9 
sudo yum install libpq-devel 

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




