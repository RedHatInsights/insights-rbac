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
from management.workspace.filters import WorkspaceAccessFilterBackend, WorkspaceObjectAccessMixin
from management.workspace.service import WorkspaceService
from psycopg2.errors import DeadlockDetected, SerializationFailure
from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.filters import OrderingFilter
from rest_framework.permissions import SAFE_METHODS
from rest_framework.request import Request
from rest_framework.response import Response

from api.common.pagination import V2ResultsSetPagination
from .model import Workspace
from .serializer import WorkspaceSerializer, WorkspaceWithAncestrySerializer
from ..utils import flatten_validation_error, validate_uuid

INCLUDE_ANCESTRY_KEY = "include_ancestry"
VALID_BOOLEAN_VALUES = ["true", "false"]

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class WorkspacePagination(V2ResultsSetPagination):
    """Custom pagination for Workspace API with higher max_limit."""

    # 3000 - max limit of count of workspaces per org id - UI needs to list all workspaces for main page
    max_limit = 3000


class WorkspaceViewSet(WorkspaceObjectAccessMixin, BaseV2ViewSet):
    """Workspace View.

    A viewset that provides default `create()`, `destroy` and `retrieve()`.

    Access control is handled by:
    - WorkspaceAccessPermission: Coarse-grained endpoint access
    - WorkspaceAccessFilterBackend: Queryset filtering via Kessel Inventory API
    - WorkspaceObjectAccessMixin: 404 for inaccessible workspaces (no existence leak)
    """

    permission_classes = (WorkspaceAccessPermission,)
    queryset = Workspace.objects.annotate()
    serializer_class = WorkspaceSerializer
    pagination_class = WorkspacePagination
    ordering_fields = ("name", "created", "modified", "type")
    ordering = ("name",)
    # WorkspaceAccessFilterBackend must be first to filter by access before other filters
    filter_backends = (WorkspaceAccessFilterBackend, filters.DjangoFilterBackend, OrderingFilter)

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

    def get_object(self):
        """Get the object, validating the UUID first."""
        pk = self.kwargs.get("pk")
        if pk is not None:
            validate_uuid(pk, "workspace uuid validation")
        return super().get_object()

    def check_permissions(self, request):
        """Pre-validate business rules before permission checks.

        Ensures business rule errors (400/404) take priority over permission
        errors (403) for all users. This is critical in V2 mode where the
        permission class checks create/move access via Inventory API.
        """
        if self.action == "create":
            self._pre_validate_create(request)
        elif self.action == "move":
            self._pre_validate_move_business_rules(request)
        super().check_permissions(request)

    def _pre_validate_create(self, request: Request) -> None:
        """Pre-validate create parameters before permission checks.

        Extracts request data and delegates business rule validation to the
        service layer. Covers CSV tests: 3.03, 3.11/3.12, 3.16.
        """
        parent_id = request.data.get("parent_id")
        if parent_id:
            validate_uuid(parent_id, "parent_id uuid validation")
        self._service.pre_validate_create(parent_id, request.data.get("name"), request.tenant)

    def _pre_validate_move_business_rules(self, request: Request) -> None:
        """Pre-validate move business rules before permission checks.

        Extracts request data, validates UUID formats, and delegates business
        rule validation to the service layer.
        Covers CSV tests: 7.02, 7.04, 7.06, 7.07, 7.11, 7.12, 7.13-7.15.
        """
        target_id_str = request.data.get("parent_id")
        if not target_id_str:
            raise serializers.ValidationError({"parent_id": "The 'parent_id' field is required."})
        validate_uuid(target_id_str)
        target_workspace_id = uuid.UUID(target_id_str)

        pk = self.kwargs.get("pk")
        if pk is None:
            return
        validate_uuid(pk, "workspace uuid validation")

        workspace = Workspace.objects.filter(id=pk, tenant=request.tenant).first()
        if workspace is None:
            return  # Let normal flow handle nonexistent source (7.10 → 404)

        self._service.pre_validate_move(workspace)
        self._service.pre_validate_move_target(workspace, target_workspace_id, request.tenant)

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
        """Get a workspace.

        Pre-validates query parameters and tenant ownership before permission/access
        checks to ensure business rules (400/403) take priority over access control (404).
        """
        # Validate include_ancestry before permission checks so ALL users get 400 for invalid values
        validate_and_get_key(request.query_params, INCLUDE_ANCESTRY_KEY, VALID_BOOLEAN_VALUES, "false")

        # Cross-tenant check: return 403 if workspace belongs to a different organization
        pk = self.kwargs.get("pk")
        if pk is not None:
            validate_uuid(pk, "workspace uuid validation")
            if Workspace.objects.filter(id=pk).exclude(tenant=request.tenant).exists():
                raise PermissionDenied("Workspace is outside of the organization.")

        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Get a list of workspaces.

        Access filtering is handled by WorkspaceAccessFilterBackend.
        Ordering is handled by OrderingFilter (supports ?order_by=name or ?order_by=-name).
        This method only handles additional query parameter filtering.
        """
        all_types = "all"
        # Use filter_queryset to apply all filter backends (including access filtering and ordering)
        queryset = self.filter_queryset(self.get_queryset())

        type_values = Workspace.Types.values + [all_types]
        type_field = validate_and_get_key(request.query_params, "type", type_values, all_types)
        name = request.query_params.get("name")
        id_filter = request.query_params.get("ids")

        # Validate name parameter: treat empty strings as "return all", reject NUL characters
        if name is not None:
            if not name.strip():
                name = None  # Treat empty name as unset, returning all results
            elif "\x00" in name:
                raise serializers.ValidationError({"name": "The 'name' query parameter contains invalid characters."})

        # Validate and filter by ids parameter (comma-separated list of UUIDs)
        if id_filter is not None:
            if not id_filter.strip():
                id_filter = None  # Treat empty ids as unset, returning all results
            else:
                if "\x00" in id_filter:
                    raise serializers.ValidationError(
                        {"ids": "The 'ids' query parameter contains invalid characters."}
                    )

                ids = list(
                    dict.fromkeys(stripped for id_val in id_filter.split(",") if (stripped := id_val.strip().lower()))
                )

                for workspace_id in ids:
                    validate_uuid(workspace_id, "workspace id filter")
                queryset = queryset.filter(id__in=ids)

                # When filtering by ids, default to standard type unless type is explicitly specified
                if "type" not in request.query_params:
                    type_field = Workspace.Types.STANDARD

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

        Pre-validates business rules before access control to ensure that
        undeletable workspaces (non-standard types, workspaces with children)
        always return 400 regardless of user permissions. Without this,
        the FilterBackend would deny access first (404) for users without
        delete permission, hiding the real reason the workspace can't be deleted.
        """
        pk = self.kwargs.get("pk")
        if pk is not None:
            validate_uuid(pk, "workspace uuid validation")
            workspace = Workspace.objects.filter(id=pk, tenant=request.tenant).first()
            if workspace is not None:
                self._service.pre_validate_destroy(workspace)
        return super().destroy(request, *args, **kwargs)

    def perform_destroy(self, instance):
        """Delegate to service for destroy logic."""
        self._service.destroy(instance)

    @transaction.atomic()
    def update(self, request, *args, **kwargs):
        """Update a workspace.

        Pre-validates business rules before access control to ensure that
        non-updatable workspaces (non-standard types) and duplicate names
        always return 400 regardless of user permissions. Without this, the
        FilterBackend would deny access first (404) for users without edit
        permission, hiding the real reason the workspace can't be updated.
        """
        pk = self.kwargs.get("pk")
        if pk is not None:
            validate_uuid(pk, "workspace uuid validation")
            workspace = Workspace.objects.filter(id=pk, tenant=request.tenant).first()
            if workspace is not None:
                self._service.pre_validate_update(workspace, new_name=request.data.get("name"))
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

        Pre-validates that the source workspace is a standard type before access control checks.
        Non-standard workspaces (root, default, ungrouped-hosts) can never be moved regardless
        of user permissions. Without this, the FilterBackend would deny access first (404) for
        users without edit permission, hiding the real reason the workspace can't be moved.

        Note: Access checks for both source and target workspaces are handled by
        WorkspaceAccessPermission.has_permission() before this method is called.
        """
        target_workspace_id = self._parent_id_query_param_validation(request)

        # Pre-validate non-standard workspace type before FilterBackend access check
        pk = self.kwargs.get("pk")
        if pk is not None:
            validate_uuid(pk, "workspace uuid validation")
            workspace = Workspace.objects.filter(id=pk, tenant=request.tenant).first()
            if workspace is not None:
                self._service.pre_validate_move(workspace)

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
                status=status.HTTP_404_NOT_FOUND,
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
