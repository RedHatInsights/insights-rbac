#
# Copyright 2025 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""View for RoleV2 management."""

import logging

import pgtransaction
from django.db import OperationalError
from management.base_viewsets import BaseV2ViewSet
from management.permissions.role_access import RoleAccessPermission
from management.role.v2_model import CustomRoleV2
from management.role.v2_serializer import RoleV2Serializer
from psycopg2.errors import DeadlockDetected, SerializationFailure
from rest_framework import status
from rest_framework.response import Response

logger = logging.getLogger(__name__)


class RoleV2ViewSet(BaseV2ViewSet):
    """
    RoleV2 ViewSet.

    Provides create, list, retrieve, update, and delete operations for custom roles.

    Responsibilities (per DDD layering):
    - Define mapping to HTTP semantics (verbs, pagination, etc.)
    - Call Serializer (and rarely Service directly for operations like delete)
    - Never throw validation errors directly - let Serializer handle that

    Access control is handled by RoleAccessPermission.
    """

    permission_classes = (RoleAccessPermission,)
    queryset = CustomRoleV2.objects.all()
    serializer_class = RoleV2Serializer
    lookup_field = "uuid"

    def get_queryset(self):
        """Get queryset filtered by tenant."""
        return (
            super()
            .get_queryset()
            .filter(tenant=self.request.tenant)
            .prefetch_related("permissions")
            .order_by("name", "-modified")
        )

    @pgtransaction.atomic(isolation_level=pgtransaction.SERIALIZABLE, retry=3)
    def _create_atomic(self, request, *args, **kwargs):
        """
        Create a role atomically with SERIALIZABLE isolation level and automatic retries.

        The SERIALIZABLE isolation level ensures the highest data consistency by preventing
        concurrent transactions from interfering with each other. This is important for
        role creation to ensure unique name constraints are properly enforced even under
        concurrent requests.

        When conflicts occur (e.g., two transactions trying to create roles with the same
        name simultaneously), PostgreSQL raises SerializationFailure. The retry=3 parameter
        automatically retries the transaction up to 3 times when SerializationFailure or
        DeadlockDetected errors occur.
        """
        return super().create(request=request, args=args, kwargs=kwargs)

    def create(self, request, *args, **kwargs):
        """
        Create a custom role.

        POST /api/v2/roles/

        Request body:
            {
                "name": "Custom Role Name",
                "description": "Role description",
                "permissions": [
                    {
                        "application": "inventory",
                        "resource_type": "hosts",
                        "operation": "read"
                    }
                ]
            }

        Returns:
            201: Role created successfully
            400: Validation error (invalid permissions, missing fields)
            401: Unauthorized
            403: Forbidden
            409: Conflict (serialization failure after retries exhausted)
            500: Server error
        """
        try:
            return self._create_atomic(request, *args, **kwargs)
        except OperationalError as e:
            # Django wraps psycopg2 errors in OperationalError
            if hasattr(e, "__cause__"):
                if isinstance(e.__cause__, SerializationFailure):
                    logger.exception("SerializationFailure in role creation operation")
                    return Response(
                        {"detail": "Too many concurrent updates. Please retry."},
                        status=status.HTTP_409_CONFLICT,
                    )
                elif isinstance(e.__cause__, DeadlockDetected):
                    logger.exception("DeadlockDetected in role creation operation")
                    return Response(
                        {"detail": "Internal server error in concurrent updates. Please try again later."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )
            raise
