#!/bin/bash

set -ex

echo "RUN THE UNIT TESTS"
pip install --upgrade pip
pip install pipenv
pip install tox

echo "testing for db server--start"

curl "http://localhost:15432"

echo "testing for db server--end"

tox -r
