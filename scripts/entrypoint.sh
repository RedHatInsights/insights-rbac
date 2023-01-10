#!/bin/bash

set -e
cd $APP_HOME
gunicorn rbac.wsgi --access-logfile=- --config gunicorn_conf.py --preload