#!/bin/sh
# One-shot: Django migrations + platform seeds.
set -eu

cd /opt/rbac/rbac

echo "Running migrations..."
python manage.py migrate --noinput

echo "Running seeds..."
python manage.py seeds

echo "Migrations and seeds complete"
