#!/bin/bash

export ACCESS_CACHE_CONNECT_SIGNALS=False

echo "Starting init container script."

echo "Running schema migrations <----"
python /opt/app-root/src/rbac/manage.py migrate --noinput
echo "Running seeds <-------"
python /opt/app-root/src/rbac/manage.py seeds
