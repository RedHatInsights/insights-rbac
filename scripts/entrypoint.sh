#!/bin/bash

set -e
cd $APP_HOME
gunicorn rbac.asgi --access-logfile=- --config gunicorn.py --preload