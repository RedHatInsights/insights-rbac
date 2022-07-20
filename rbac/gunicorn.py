"""Gunicorn configuration file."""
import multiprocessing
import os

bind = "unix:/var/run/rbac/gunicorn.sock"
cpu_resources = int(os.environ.get("POD_CPU_LIMIT", multiprocessing.cpu_count()))
workers = cpu_resources * int(os.environ.get("SERVER_WORKER_MULTIPLIER", 2))
threads = 10
limit_request_field_size = 16380
