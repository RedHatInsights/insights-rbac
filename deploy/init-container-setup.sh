#!/bin/bash

export ACCESS_CACHE_CONNECT_SIGNALS=False
export MAX_SEED_THREADS=2

echo "Starting init container script."
echo "Run in EPH ENV = ${EPH_ENV}"

if [ ${EPH_ENV} == "True" ];
then
    echo "Running migrate_schemas <----"
    python /opt/app-root/src/rbac/manage.py migrate_schemas --noinput --executor=parallel
    echo "Running seeds <-------"
    python /opt/app-root/src/rbac/manage.py seeds
else
    echo "Not run in EPH ENV, exiting."
fi

