#!/bin/bash

set -ex

echo "RUN THE UNIT TESTS"
pip install --upgrade pip
pip install pipenv
pip install tox

DB_HOST=localhost DB_PORT=15432 bash -c 'printf "" 2>>/dev/null >>/dev/tcp/${DB_HOST}/${DB_PORT}'

echo $? "testing for the db server"


tox -r
