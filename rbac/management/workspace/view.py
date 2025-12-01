#
# Copyright 2019 Red Hat, Inc.
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
"""View for Workspace management."""

import logging
import uuid

import pgtransaction
from django.core.exceptions import ValidationError
from django.db import OperationalError, transaction
from django_filters import rest_framework as filters
from management.base_viewsets import BaseV2ViewSet
from management.permissions.workspace_access import WorkspaceAccessPermission
from management.utils import validate_and_get_key
from management.workspace.service import WorkspaceService
from psycopg2.errors import DeadlockDetected, SerializationFailure
from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter
from rest_framework.permissions import SAFE_METHODS
from rest_framework.request import Request
from rest_framework.response import Response

from .model import Workspace
from .serializer import WorkspaceSerializer, WorkspaceWithAncestrySerializer
from ..utils import flatten_validation_error, validate_uuid

INCLUDE_ANCESTRY_KEY = "include_ancestry"
VALID_BOOLEAN_VALUES = ["true", "false"]

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class WorkspaceViewSet(BaseV2ViewSet):
    """Workspace View.

    A viewset that provides default `create()`, `destroy` and `retrieve()`.

    """

    permission_classes = (WorkspaceAccessPermission,)
    queryset = Workspace.objects.annotate()
    serializer_class = WorkspaceSerializer
    ordering_fields = ("name",)
    ordering = ("name",)
    filter_backends = (filters.DjangoFilterBackend, OrderingFilter)

    def __init__(self, **kwargs):
        """Init viewset."""
        super().__init__(**kwargs)
        self._service = WorkspaceService()

    def get_serializer_class(self):
        """Get serializer class based on route."""
        if self.action == "retrieve":
            include_ancestry = validate_and_get_key(
                self.request.query_params, INCLUDE_ANCESTRY_KEY, VALID_BOOLEAN_VALUES, "false"
            )
            if include_ancestry == "true":
                return WorkspaceWithAncestrySerializer
        return super().get_serializer_class()

    def get_queryset(self):
        """Get queryset override."""
        if self.request.method not in SAFE_METHODS:
            return super().get_queryset().select_for_update()
        return super().get_queryset()

    @pgtransaction.atomic(isolation_level=pgtransaction.SERIALIZABLE, retry=3)
    def _create_atomic(self, request, *args, **kwargs):
        """
        Create a workspace atomically with SERIALIZABLE isolation level and automatic retries.

        The SERIALIZABLE isolation level ensures the highest data consistency by preventing
        concurrent transactions from interfering with each other. However, when conflicts occur
        (e.g., two transactions trying to create workspaces simultaneously), PostgreSQL raises
        SerializationFailure. The retry=3 parameter automatically retries the transaction up to
        3 times when SerializationFailure or DeadlockDetected errors occur. This is expected
        behavior and retrying usually succeeds as concurrent transactions complete.
        """
        tenant = request.tenant
        parent_id = request.data.get("parent_id")

        if parent_id and tenant:
            if not Workspace.objects.filter(id=parent_id, tenant=tenant).exists():
                raise serializers.ValidationError(
                    {"parent_id": f"Parent workspace '{parent_id}' doesn't exist in tenant"}
                )
        return super().create(request=request, args=args, kwargs=kwargs)

    def create(self, request, *args, **kwargs):
        """Create a Workspace."""
        try:
            return self._create_atomic(request, *args, **kwargs)
        except TimeoutError as e:
            logger.exception("TimeoutError in workspace creation operation")
            return Response(
                {"detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except OperationalError as e:
            # Django wraps psycopg2 errors in OperationalError
            if hasattr(e, "__cause__"):
                if isinstance(e.__cause__, SerializationFailure):
                    logger.exception("SerializationFailure in workspace creation operation")
                    return Response(
                        {"detail": "Too many concurrent updates. Please retry."}, status=status.HTTP_409_CONFLICT
                    )
                elif isinstance(e.__cause__, DeadlockDetected):
                    logger.exception("DeadlockDetected in workspace creation operation")
                    return Response(
                        {"detail": "Internal server error in concurrent updates. Please try again later."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )
            raise
        except ValidationError as e:
            message = ""
            for field, error_message in flatten_validation_error(e):
                if "unique_workspace_name_per_parent" in error_message:
                    message = "A workspace with the same name already exists under the parent."
                    break
                if "__all__" in field:
                    message = error_message
                    break
            if message:
                raise serializers.ValidationError(message)
            raise

    def retrieve(self, request, *args, **kwargs):
        """Get a workspace."""
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Get a list of workspaces."""
        all_types = "all"
        queryset = self.get_queryset()
        if getattr(request, "permission_tuples", None):
            permitted_wss = [tuple[1] for tuple in request.permission_tuples]
            queryset = queryset.filter(id__in=permitted_wss)
        type_values = Workspace.Types.values + [all_types]
        type_field = validate_and_get_key(request.query_params, "type", type_values, all_types)
        name = request.query_params.get("name")

        # Validate name parameter: reject empty strings and strings containing NUL characters
        if name is not None:
            if not name.strip():
                raise serializers.ValidationError({"name": "The 'name' query parameter cannot be empty."})
            if "\x00" in name:
                raise serializers.ValidationError({"name": "The 'name' query parameter contains invalid characters."})

        if type_field != all_types:
            queryset = queryset.filter(type=type_field)
        if name:
            queryset = queryset.filter(name__iexact=name.lower())

        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(page, many=True)
        return self.get_paginated_response(serializer.data)

    @transaction.atomic()
    def destroy(self, request, *args, **kwargs):
        """
        Destroy the instance.

        Overridden only to add transaction.
        """
        return super().destroy(request, *args, **kwargs)

    def perform_destroy(self, instance):
        """Delegate to service for destroy logic."""
        self._service.destroy(instance)

    @transaction.atomic()
    def update(self, request, *args, **kwargs):
        """Update a workspace."""
        return super().update(request, *args, **kwargs)

    @pgtransaction.atomic(isolation_level=pgtransaction.SERIALIZABLE, retry=3)
    def _move_atomic(self, request):
        """
        Move a workspace atomically with SERIALIZABLE isolation level and automatic retries.

        The SERIALIZABLE isolation level ensures the highest data consistency by preventing
        concurrent transactions from interfering with each other. However, when conflicts occur
        (e.g., two transactions trying to move workspaces simultaneously), PostgreSQL raises
        SerializationFailure. The retry=3 parameter automatically retries the transaction up to
        3 times when SerializationFailure or DeadlockDetected errors occur. This is expected
        behavior and retrying usually succeeds as concurrent transactions complete.

        Note: Access checks for both source and target workspaces are handled by
        WorkspaceAccessPermission.has_permission() before this method is called.
        """
        target_workspace_id = self._parent_id_query_param_validation(request)
        workspace = self.get_object()
        serializer = self.get_serializer(workspace)
        return serializer.move(workspace, target_workspace_id)

    @action(detail=True, methods=["post"], url_path="move")
    def move(self, request, *args, **kwargs):
        """Move a workspace."""
        try:
            response_data = self._move_atomic(request)
            return Response(response_data, status=status.HTTP_200_OK)
        except OperationalError as e:
            # Django wraps psycopg2 errors in OperationalError
            if hasattr(e, "__cause__"):
                if isinstance(e.__cause__, SerializationFailure):
                    logger.exception(
                        "SerializationFailure in workspace movement operation, ws id: %s", kwargs.get("pk")
                    )
                    return Response(
                        {"detail": "Too many concurrent updates. Please retry."}, status=status.HTTP_409_CONFLICT
                    )
                elif isinstance(e.__cause__, DeadlockDetected):
                    logger.exception("DeadlockDetected in workspace movement operation, ws id: %s", kwargs.get("pk"))
                    return Response(
                        {"detail": "Internal server error in concurrent updates. Please try again later."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )
            raise
        except Workspace.DoesNotExist:
            logger.exception("Target Workspace not found during operation, ws id: %s", kwargs.get("pk"))
            return Response(
                {"detail": "Workspace not found."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except ValidationError as e:
            message = ""
            for field, error_message in flatten_validation_error(e):
                if "unique_workspace_name_per_parent" in error_message:
                    message = "A workspace with the same name already exists under the target parent."
                    break
                if "__all__" in field:
                    message = error_message
                    break
            raise serializers.ValidationError(message)

    @staticmethod
    def _parent_id_query_param_validation(request: Request) -> uuid.UUID:
        """Validate the parent_id query parameter."""
        new_parent_id = request.data.get("parent_id")
        if not new_parent_id:
            raise serializers.ValidationError({"parent_id": "The 'parent_id' field is required."})
        validate_uuid(new_parent_id)
        return uuid.UUID(new_parent_id)
