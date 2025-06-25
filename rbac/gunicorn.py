"""Gunicorn configuration file."""

import multiprocessing
import os
import logging

from prometheus_client import multiprocess

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

logger = logging.getLogger(__name__)


def post_worker_init(worker):
    """Initialize FEATURE_FLAGS in each worker process after forking."""
    try:
        # Import here to avoid issues during gunicorn startup
        from feature_flags import FEATURE_FLAGS

        logger.info(f"*** INITIALIZING FEATURE_FLAGS IN WORKER {worker.pid} ***")
        FEATURE_FLAGS.initialize()
        logger.info(f"*** FEATURE_FLAGS INITIALIZED IN WORKER {worker.pid} ***")
    except Exception as e:
        logger.warning(f"Failed to initialize FEATURE_FLAGS in worker {worker.pid}: {e}")


def child_exit(server, worker):
    """Watches for workers to exit and marks them as dead in prometheus."""
    # See: https://prometheus.github.io/client_python/multiprocess/
    multiprocess.mark_process_dead(worker.pid)
