#!/bin/bash

export ACCESS_CACHE_CONNECT_SIGNALS=False

echo "Starting init container script."
MIGRATE=False #$(echo "$MIGRATE_AND_SEED_ON_INIT" | tr '[:upper:]' '[:lower:]')

if [[ "$MIGRATE" = "true" ]]
then
    echo "Running schema migrations <----"
    python /opt/rbac/rbac/manage.py migrate --noinput
    echo "Running seeds <-------"
    python /opt/rbac/rbac/manage.py seeds
else
    echo "Migrations should not be run <----"
fi