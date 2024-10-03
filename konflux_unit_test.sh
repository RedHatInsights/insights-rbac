#!/bin/bash

set -ex

echo "RUN THE UNIT TESTS"
pip install --upgrade pip
pip install pipenv
pip install tox

echo "hit tox"

tox -r
