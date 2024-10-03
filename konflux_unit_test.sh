#!/bin/bash

set -ex

echo "RUN THE UNIT TESTS"
pip install --upgrade pip
pip install pipenv
pip install tox

echo "testing for db server"
ls
cd
ls -la
ls /dev/

DB_HOST=localhost
DB_PORT=15432
printf "" 2>>/dev/null >>/dev/tcp/${DB_HOST}/${DB_PORT}

echo $?
echo "testing for db server--end"
curl "http://localhost:15432"
tox -r
