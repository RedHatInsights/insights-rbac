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
import requests
from django.db import transaction
from rest_framework import status
from rest_framework.response import Response


class SpiceDb:
    """SpiceDB decorators."""

    def sync(view_method):
        """Sync to SpiceDB."""

        def _sync(self, request, *args, **kwargs):
            with transaction.atomic():
                try:
                    view_response = view_method(self, request, *args, **kwargs)
                    spice_db_response = requests.post(
                        "http://localhost:8000/api/rbac/v1/spicedb/", json=view_response.data
                    )
                    spice_db_response.raise_for_status()
                except requests.exceptions.RequestException as e:
                    transaction.set_rollback(True)
                    view_response = Response(
                        {
                            "errors": [
                                {
                                    "detail": f"Dependent SpiceDB call failed with: {e.response.reason}",
                                    "spice_db_status": spice_db_response.status_code,
                                }
                            ]
                        },
                        status=status.HTTP_424_FAILED_DEPENDENCY,
                    )
                except Exception as e:
                    transaction.set_rollback(True)
                    view_response = Response(
                        {"errors": [{"detail": f"Failed to save record with: {e}"}]},
                        status=status.HTTP_424_FAILED_DEPENDENCY,
                    )
                return view_response

        return _sync
