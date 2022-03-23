#!/bin/sh
sleep 15
python rbac/manage.py migrate
DJANGO_READ_DOT_ENV_FILE=True python rbac/manage.py runserver 0.0.0.0:8000
