#    Copyright 2023 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""
WSGI config for rbac project.

It exposes the WSGI callable as a module-level variable named ``application``.
For more information on this file, see
https://docs.djangoproject.com/en/2.0/howto/deployment/wsgi/
"""

import os
import sys
import logging

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "rbac.settings")

# pylint: disable=invalid-name
application = get_wsgi_application()

# Initialize FEATURE_FLAGS based on environment
# - In production (gunicorn): handled by post_worker_init hook in gunicorn.py
# - In development (runserver, etc.): handled here
logger = logging.getLogger(__name__)


def is_running_gunicorn():
    """Check if we're running under gunicorn."""
    return "gunicorn" in sys.argv[0] or "gunicorn" in os.environ.get("SERVER_SOFTWARE", "")


if not is_running_gunicorn():
    try:
        from feature_flags import FEATURE_FLAGS

        logger.info("*** INITIALIZING FEATURE_FLAGS IN WSGI (NON-GUNICORN) ***")
        FEATURE_FLAGS.initialize()
        logger.info("*** FEATURE_FLAGS INITIALIZED IN WSGI ***")
    except Exception as e:
        logger.warning(f"Failed to initialize FEATURE_FLAGS in WSGI: {e}")
else:
    logger.info("*** FEATURE_FLAGS initialization will be handled by gunicorn post_worker_init hook ***")
