#!/bin/bash

set -ex

echo "START THE DATABASE"
pip install --upgrade pip
pip3 install pipenv
pip3 install tox

make start-db

tox -r

make stop-compose