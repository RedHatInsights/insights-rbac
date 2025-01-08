#!/bin/bash

export ACCESS_CACHE_CONNECT_SIGNALS=False

echo "Starting init container script."
MIGRATE=$(echo "$MIGRATE_AND_SEED_ON_INIT" | tr '[:upper:]' '[:lower:]')

if [[ "$MIGRATE" = "true" ]]
then
    # In ephemeral/test, this makes sure the db is available when init container run
    python /opt/rbac/rbac/manage.py wait_for_db

    echo "Running schema migrations <----"
    python /opt/rbac/rbac/manage.py migrate --noinput
    echo "Running seeds <-------"
    python /opt/rbac/rbac/manage.py seeds
else
    echo "Migrations should not be run <----"
fi
