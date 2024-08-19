"""Gunicorn configuration file."""

import multiprocessing
import os

from rbac.env import ENVIRONMENT

CLOWDER_PORT = "8080"
if ENVIRONMENT.bool("CLOWDER_ENABLED", default=False):
    from app_common_python import LoadedConfig

    CLOWDER_PORT = LoadedConfig.publicPort

bind = f"0.0.0.0:{CLOWDER_PORT}"

cpu_resources = int(os.environ.get("POD_CPU_LIMIT", multiprocessing.cpu_count()))
workers = cpu_resources * int(os.environ.get("GUNICORN_WORKER_MULTIPLIER", 2))
threads = int(os.environ.get("GUNICORN_THREAD_LIMIT", 10))
limit_request_field_size = 16380
