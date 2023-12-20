#
# Copyright 2023 Red Hat, Inc.
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
"""Decorators for management module."""
import logging

import requests
from django.db import transaction
from rest_framework import status
from rest_framework.response import Response

from rbac.settings import SPICE_DB_TIMEOUT, SPICE_DB_URL

logger = logging.getLogger(__name__)


class SpiceDb:
    """SpiceDB decorators."""

    def sync(**options):
        """Sync to SpiceDB."""

        def _sync_wrapper(view_method):
            def _sync(self, request, *args, **kwargs):
                with transaction.atomic():
                    try:
                        view_response = view_method(self, request, *args, **kwargs)
                        spice_db_response = _call_spice_db(view_response, request, **options)
                        spice_db_response.raise_for_status()
                        logger.info(f"SpiceDB token received: {spice_db_response.json()['spice_db_token']}")
                    except requests.exceptions.ReadTimeout as e:
                        view_response = _error_response(f"Dependent SpiceDB call timed out: {e}")
                    except requests.exceptions.RequestException as e:
                        error_msg = (
                            f"Dependent SpiceDB call failed with a "
                            f"{spice_db_response.status_code}: {e.response.reason} for: {view_response.data}"
                        )
                        view_response = _error_response(error_msg)
                    except Exception as e:
                        error_msg = f"Failed to save record with: {e}"
                        view_response = _error_response(error_msg)
                    return view_response

            return _sync

        def _call_spice_db(view_response, request, **options):
            data = {
                "resource_type": options["resource_type"],
                "action": options["action"],
                "resource": view_response.data,
                "mock_status": request.data.get("mock_status", "400"),
            }
            return requests.post(f"{SPICE_DB_URL}/api/rbac/v1/spicedb/", json=data, timeout=SPICE_DB_TIMEOUT)

        def _error_response(error_msg):
            _rollback_and_log(error_msg)
            return Response({"errors": [{"detail": error_msg}]}, status=status.HTTP_424_FAILED_DEPENDENCY)

        def _rollback_and_log(error_msg):
            transaction.set_rollback(True)
            logger.error(error_msg)

        return _sync_wrapper
