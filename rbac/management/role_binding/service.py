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
"""Service layer for role binding management."""

import logging
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from django.conf import settings
from django.db import transaction
from django.db.models import Max, Prefetch, Q, QuerySet
from django.db.models.aggregates import Count
from google.protobuf import json_format
from internal.jwt_utils import JWTManager, JWTProvider
from kessel.relations.v1beta1 import common_pb2, lookup_pb2, lookup_pb2_grpc
from management.atomic_transactions import atomic
from management.cache import JWTCache
from management.exceptions import InvalidFieldError, NotFoundError, RequiredFieldError
from management.group.model import Group
from management.group.platform import DefaultGroupNotAvailableError, GlobalPolicyIdService
from management.permission.scope_service import Scope
from management.principal.model import Principal
from management.role.platform import platform_v2_role_uuid_for
from management.role.v2_model import PlatformRoleV2, RoleV2
from management.role_binding.model import RoleBinding, RoleBindingGroup
from management.subject import SubjectService, SubjectType
from management.tenant_mapping.model import DefaultAccessType, TenantMapping
from management.utils import create_client_channel_relation
from management.workspace.model import Workspace

from api.models import Tenant


@dataclass
class UpdateRoleBindingResult:
    """Result of updating role bindings for a subject on a resource."""

    subject_type: str
    roles: list[RoleV2]
    resource_id: str
    resource_type: str
    subject: Group | Principal


logger = logging.getLogger(__name__)

# Lazily instantiate the JWT helpers once so all requests reuse the same objects.
_jwt_cache = JWTCache()
_jwt_provider = JWTProvider()
_jwt_manager = JWTManager(_jwt_provider, _jwt_cache)


class RoleBindingService:
    """Service for role binding queries and operations."""

    def __init__(self, tenant: Tenant):
        """Initialize the service with a tenant."""
        from management.role.v2_service import RoleV2Service

        self.tenant = tenant
        self.subject_service = SubjectService(tenant)
        self.role_service = RoleV2Service()

    def get_role_bindings_by_subject(self, params: dict) -> QuerySet:
        """Get role bindings grouped by subject (group) from a dictionary of parameters.

        Args:
            params: Dictionary of validated query parameters (from input serializer)

        Returns:
            QuerySet of Group objects annotated with role binding information

        Note:
            Ordering is handled by V2CursorPagination.get_ordering() to ensure
            cursor pagination works correctly with the requested order_by parameter.
        """
        resource_id = params["resource_id"]
        resource_type = params["resource_type"]
        include_inherited = params.get("parent_role_bindings", False)

        # Ensure default bindings exist (lazy creation)
        self._ensure_default_bindings_exist()

        # If parent_role_bindings is requested, lookup inherited binding UUIDs via Relations API
        binding_uuids = None
        if include_inherited:
            binding_uuids = self._lookup_binding_uuids_via_relations(resource_type, resource_id)

        # Build base queryset for the specified resource
        queryset = self._build_base_queryset(resource_id, resource_type, binding_uuids)

        # Apply subject filters
        queryset = self._apply_subject_filters(queryset, params.get("subject_type"), params.get("subject_id"))

        return queryset

    def get_resource_name(self, resource_id: str, resource_type: str) -> Optional[str]:
        """Get the name of a resource by ID and type.

        Args:
            resource_id: The resource identifier
            resource_type: The type of resource (e.g., 'workspace')

        Returns:
            Resource name or None if not found
        """
        if resource_type == "workspace":
            try:
                workspace = Workspace.objects.get(id=resource_id, tenant=self.tenant)
                return workspace.name
            except Workspace.DoesNotExist:
                logger.warning(f"Workspace {resource_id} not found for tenant {self.tenant}")
                return None
        return None

    def build_context(self, params: dict) -> dict:
        """Build serializer context with resource information from a dictionary.

        Args:
            params: Dictionary of validated query parameters (from input serializer).
                    The 'fields' key contains an already-parsed FieldSelection object or None.

        Returns:
            Context dict for output serializer
        """
        resource_id = params["resource_id"]
        resource_type = params["resource_type"]

        return {
            "resource_id": resource_id,
            "resource_type": resource_type,
            "resource_name": self.get_resource_name(resource_id, resource_type),
            "field_selection": params.get("fields"),
        }

    def _build_base_queryset(
        self, resource_id: str, resource_type: str, binding_uuids: Optional[Sequence[str]] = None
    ) -> QuerySet:
        """Build base queryset of groups with role bindings for a resource.

        Args:
            resource_id: The resource identifier
            resource_type: The type of resource
            binding_uuids: Optional list of binding UUIDs to include (for inherited bindings)

        Returns:
            Annotated QuerySet of Group objects
        """
        # Build filter for bindings - either by resource or by explicit UUIDs
        if binding_uuids is not None:
            # Include both direct bindings and inherited bindings by UUID
            binding_filter = Q(
                role_binding_entries__binding__resource_type=resource_type,
                role_binding_entries__binding__resource_id=resource_id,
            ) | Q(role_binding_entries__binding__uuid__in=binding_uuids)
        else:
            # Only direct bindings for the specified resource
            binding_filter = Q(
                role_binding_entries__binding__resource_type=resource_type,
                role_binding_entries__binding__resource_id=resource_id,
            )

        # Get groups that have bindings matching our filter.
        # This includes tenant-specific groups and public tenant default groups.
        # No tenant filter needed since resource_id is tenant-specific.
        queryset = Group.objects.filter(binding_filter).distinct()

        # Annotate with principal count
        queryset = queryset.annotate(
            principalCount=Count("principals", filter=Q(principals__type=Principal.Types.USER), distinct=True)
        )

        # Prefetch role bindings for this resource with their roles
        # Also prefetch children for platform roles (which will be returned instead of the platform role)
        binding_queryset = (
            RoleBinding.objects.filter(resource_type=resource_type, resource_id=resource_id)
            .select_related("role")
            .prefetch_related("role__children")
        )

        # Prefetch the join table entries with the filtered bindings
        rolebinding_group_queryset = RoleBindingGroup.objects.filter(
            binding__resource_type=resource_type, binding__resource_id=resource_id
        ).prefetch_related(Prefetch("binding", queryset=binding_queryset))

        queryset = queryset.prefetch_related(
            Prefetch(
                "role_binding_entries",
                queryset=rolebinding_group_queryset,
                to_attr="filtered_bindings",
            )
        )

        # Annotate with latest modified timestamp from roles
        queryset = queryset.annotate(
            latest_modified=Max(
                "role_binding_entries__binding__role__modified",
                filter=Q(
                    role_binding_entries__binding__resource_type=resource_type,
                    role_binding_entries__binding__resource_id=resource_id,
                ),
            )
        )

        return queryset

    def _apply_subject_filters(
        self,
        queryset: QuerySet,
        subject_type: Optional[str],
        subject_id: Optional[str],
    ) -> QuerySet:
        """Apply subject type and ID filters to queryset.

        Args:
            queryset: Base queryset to filter
            subject_type: Optional subject type filter (e.g., 'group', 'user')
            subject_id: Optional subject ID filter

        Returns:
            Filtered queryset
        """
        if subject_type:
            # Currently only GROUP subject type is implemented
            if subject_type != SubjectType.GROUP:
                # Filter out all results for unsupported subject types
                return queryset.none()

        if subject_id:
            queryset = queryset.filter(uuid=subject_id)

        return queryset

    def _parse_resource_type(self, resource_type: str) -> tuple[str, str]:
        """Parse resource type into namespace and name.

        Args:
            resource_type: Resource type string, optionally prefixed with namespace
                          (e.g., "workspace" or "rbac/workspace")

        Returns:
            Tuple of (namespace, name)
        """
        if "/" in resource_type:
            parts = resource_type.split("/", 1)
            return (parts[0], parts[1])
        return ("rbac", resource_type)  # Default namespace

    def _lookup_binding_uuids_via_relations(self, resource_type: str, resource_id: str) -> Optional[list[str]]:
        """Use the Relations API to resolve binding UUIDs that affect the given resource."""
        if not settings.RELATION_API_SERVER:
            logger.warning("RELATION_API_SERVER is not configured; skipping inheritance lookup.")
            return None

        try:
            logger.info(
                "Calling _lookup_binding_uuids_via_relations for resource_type=%s, resource_id=%s",
                resource_type,
                resource_id,
            )
            resource_ns, resource_name = self._parse_resource_type(resource_type)
            token = _jwt_manager.get_jwt_from_redis()
            metadata = [("authorization", f"Bearer {token}")] if token else []
            binding_ids = set()

            with create_client_channel_relation(settings.RELATION_API_SERVER) as channel:
                stub = lookup_pb2_grpc.KesselLookupServiceStub(channel)

                # Build request in a way that is compatible with multiple proto versions.
                request_kwargs = {
                    # Mirrors: zed permission lookup-subjects rbac/workspace <id> user_grant rbac/role_binding
                    "resource": common_pb2.ObjectReference(
                        type=common_pb2.ObjectType(namespace=resource_ns, name=resource_name),
                        id=str(resource_id),
                    ),
                    "subject_type": common_pb2.ObjectType(namespace="rbac", name="role_binding"),
                }

                # Newer API versions use a 'permission' field; older ones may use 'relation'.
                # In the current schema, the permission is `user_grant` on rbac/workspace.
                request_fields = lookup_pb2.LookupSubjectsRequest.DESCRIPTOR.fields_by_name
                if "permission" in request_fields:
                    request_kwargs["permission"] = "role_binding_view"
                elif "relation" in request_fields:
                    request_kwargs["relation"] = "t_binding"

                request = lookup_pb2.LookupSubjectsRequest(**request_kwargs)
                logger.info("LookupSubjects request payload: %s", request)

                responses: Iterable[lookup_pb2.LookupSubjectsResponse] = stub.LookupSubjects(
                    request, metadata=metadata
                )
                for idx, response in enumerate(responses, start=1):
                    payload = json_format.MessageToDict(response)
                    logger.info("LookupSubjects response #%s: %s", idx, payload)
                    subject = payload.get("subject", {})
                    subject_id = subject.get("id") or subject.get("subject", {}).get("id")
                    if subject_id:
                        logger.info("Adding binding subject_id from Relations: %s", subject_id)
                        binding_ids.add(subject_id)

            result = list(binding_ids)
            logger.info(
                "Resolved %d binding UUID(s) via Relations for resource_type=%s, resource_id=%s: %s",
                len(result),
                resource_type,
                resource_id,
                result,
            )
            return result
        except Exception:  # noqa: BLE001
            logger.exception("Failed to lookup inherited bindings through Relations")
            return None

    def _ensure_default_bindings_exist(self) -> None:
        """Lazily create default role bindings if they don't exist.

        This method checks if the tenant has default role bindings by counting ADMIN bindings.
        ADMIN bindings are always created (regardless of custom groups), so if all 3 ADMIN
        bindings exist, we know default bindings have already been processed for this tenant.

        If bindings don't exist, it creates all missing bindings in a single atomic transaction.
        USER bindings are only created if the tenant has no custom default group.
        """
        try:
            mapping = self.tenant.tenant_mapping
        except TenantMapping.DoesNotExist:
            logger.debug(f"No tenant mapping for tenant {self.tenant.org_id}, skipping default bindings")
            return

        # Fast path: check if ADMIN bindings exist (always created regardless of custom group)
        # If all ADMIN bindings exist, default bindings have been processed for this tenant
        admin_binding_uuids = [mapping.default_role_binding_uuid_for(DefaultAccessType.ADMIN, s) for s in Scope]
        existing_admin_count = RoleBinding.objects.filter(uuid__in=admin_binding_uuids).count()

        if existing_admin_count == len(Scope):
            # All ADMIN bindings exist - default bindings already processed
            return

        # ADMIN bindings don't all exist - need to create missing bindings
        # Now check for custom default group (only needed when creating)
        has_custom_default_group = self._has_custom_default_group()

        # Create all missing bindings in a single transaction
        try:
            self._create_all_default_bindings(mapping, skip_user_bindings=has_custom_default_group)
        except DefaultGroupNotAvailableError:
            logger.warning(
                f"Platform roles not available, skipping default binding creation for tenant {self.tenant.org_id}"
            )
        except Exception as e:
            error_msg = f"Failed to create default bindings for tenant {self.tenant.org_id}: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e

    def _has_custom_default_group(self) -> bool:
        """Check if the tenant has a custom default group.

        A custom default group is a Group with platform_default=True that belongs
        to this tenant (not the public tenant).

        Returns:
            True if tenant has a custom default group, False otherwise
        """
        return Group.objects.filter(tenant=self.tenant, platform_default=True).exists()

    @transaction.atomic
    def _create_all_default_bindings(self, mapping: TenantMapping, skip_user_bindings: bool = False) -> None:
        """Create all default role bindings for all scopes in a single transaction.

        Creates admin default bindings for all 3 scopes, and optionally user default bindings
        (unless the tenant has a custom default group).

        Args:
            mapping: The tenant mapping containing default UUIDs
            skip_user_bindings: If True, skip creating USER default bindings
                (used when tenant has custom default group)
        """
        policy_service = GlobalPolicyIdService.shared()
        created_count = 0

        for scope in Scope:
            # Get resource info for this scope
            resource_type, resource_id = self._get_resource_for_scope(scope)
            if resource_id is None:
                logger.warning(f"Could not determine resource for scope {scope} in tenant {self.tenant.org_id}")
                continue

            for access_type in DefaultAccessType:
                # Skip USER bindings if tenant has custom default group
                if skip_user_bindings and access_type == DefaultAccessType.USER:
                    continue

                # Check if this specific binding already exists
                binding_uuid = mapping.default_role_binding_uuid_for(access_type, scope)
                if RoleBinding.objects.filter(uuid=binding_uuid).exists():
                    continue

                self._create_single_default_binding(
                    mapping=mapping,
                    access_type=access_type,
                    scope=scope,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    policy_service=policy_service,
                )
                created_count += 1

        if created_count > 0:
            logger.info(f"Created {created_count} default role bindings for tenant {self.tenant.org_id}")

    def _create_single_default_binding(
        self,
        mapping: TenantMapping,
        access_type: DefaultAccessType,
        scope: Scope,
        resource_type: str,
        resource_id: str,
        policy_service: GlobalPolicyIdService,
    ) -> None:
        """Create a single default role binding with its associated group.

        Uses the platform default groups from the public tenant rather than
        creating per-tenant groups.

        Args:
            mapping: The tenant mapping
            access_type: USER or ADMIN
            scope: The scope level
            resource_type: The resource type string
            resource_id: The resource ID string
            policy_service: Service for looking up platform role UUIDs
        """
        binding_uuid = mapping.default_role_binding_uuid_for(access_type, scope)

        # Get the platform role
        platform_role_uuid = platform_v2_role_uuid_for(access_type, scope, policy_service)
        try:
            platform_role = PlatformRoleV2.objects.get(uuid=platform_role_uuid)
        except PlatformRoleV2.DoesNotExist:
            logger.error(f"Platform role {platform_role_uuid} not found for {access_type} {scope}")
            raise DefaultGroupNotAvailableError(f"Platform role not found: {platform_role_uuid}")

        # Get the platform default group from public tenant (created by seed_group)
        if access_type == DefaultAccessType.ADMIN:
            group = Group.admin_default_set().public_tenant_only().get()
        else:
            group = Group.platform_default_set().public_tenant_only().get()

        # Create the role binding
        binding, created = RoleBinding.objects.get_or_create(
            uuid=binding_uuid,
            defaults={
                "role": platform_role,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "tenant": self.tenant,
            },
        )

        if created:
            # Create the binding-group relationship
            RoleBindingGroup.objects.get_or_create(
                group=group,
                binding=binding,
            )

    def _get_resource_for_scope(self, scope: Scope) -> tuple[str, Optional[str]]:
        """Get the resource type and ID for a given scope.

        Args:
            scope: The scope level

        Returns:
            Tuple of (resource_type, resource_id). resource_id may be None if not found.
        """
        if scope == Scope.TENANT:
            return ("tenant", self.tenant.tenant_resource_id())

        if scope == Scope.ROOT:
            try:
                workspace = Workspace.objects.root(tenant=self.tenant)
                return ("workspace", str(workspace.id))
            except Workspace.DoesNotExist:
                return ("workspace", None)

        if scope == Scope.DEFAULT:
            try:
                workspace = Workspace.objects.default(tenant=self.tenant)
                return ("workspace", str(workspace.id))
            except Workspace.DoesNotExist:
                return ("workspace", None)

        return ("unknown", None)

    @transaction.atomic
    def delete_user_default_bindings(self) -> None:
        """Delete USER default role bindings for the tenant.

        This should be called when a custom default group is created for the tenant.
        ADMIN default bindings are NOT affected (admin access is not customizable).

        Note: This only deletes the RoleBinding and RoleBindingGroup records.
        The public tenant's platform_default Group is shared and not deleted.
        """
        try:
            mapping = self.tenant.tenant_mapping
        except TenantMapping.DoesNotExist:
            logger.debug(f"No tenant mapping for tenant {self.tenant.org_id}, nothing to delete")
            return

        # Get all USER binding UUIDs
        user_binding_uuids = [mapping.default_role_binding_uuid_for(DefaultAccessType.USER, scope) for scope in Scope]

        # Delete all in one query (RoleBindingGroup entries cascade)
        deleted_count, _ = RoleBinding.objects.filter(uuid__in=user_binding_uuids).delete()

        if deleted_count > 0:
            logger.info(
                f"Deleted {deleted_count} USER default role bindings for tenant {self.tenant.org_id} "
                f"(custom default group created)"
            )

    @transaction.atomic
    def restore_user_default_bindings(self) -> None:
        """Restore USER default role bindings for the tenant.

        This should be called when a custom default group is deleted for the tenant.
        Creates USER default bindings for all scopes (DEFAULT, ROOT, TENANT).

        Note: ADMIN default bindings are not affected by this method.
        """
        try:
            mapping = self.tenant.tenant_mapping
        except TenantMapping.DoesNotExist:
            logger.debug(f"No tenant mapping for tenant {self.tenant.org_id}, cannot restore bindings")
            return

        try:
            policy_service = GlobalPolicyIdService.shared()

            for scope in Scope:
                # Check if binding already exists
                binding_uuid = mapping.default_role_binding_uuid_for(DefaultAccessType.USER, scope)
                if RoleBinding.objects.filter(uuid=binding_uuid).exists():
                    continue

                resource_type, resource_id = self._get_resource_for_scope(scope)
                if resource_id is None:
                    logger.warning(f"Could not determine resource for scope {scope} in tenant {self.tenant.org_id}")
                    continue

                self._create_single_default_binding(
                    mapping=mapping,
                    access_type=DefaultAccessType.USER,
                    scope=scope,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    policy_service=policy_service,
                )

            logger.info(
                f"Restored USER default role bindings for tenant {self.tenant.org_id} "
                f"(custom default group deleted)"
            )
        except DefaultGroupNotAvailableError:
            logger.warning(
                f"Platform roles not available, could not restore default bindings for tenant {self.tenant.org_id}"
            )
        except Exception as e:
            logger.error(f"Failed to restore default bindings for tenant {self.tenant.org_id}: {e}")

    @atomic
    def update_role_bindings_for_subject(
        self,
        resource_type: str,
        resource_id: str,
        subject_type: str,
        subject_id: str,
        role_ids: list[str],
    ) -> UpdateRoleBindingResult:
        """Update role bindings for a subject on a resource.

        This replaces all existing role bindings for the subject on the resource
        with the provided roles.

        Args:
            resource_type: The type of resource (e.g., 'workspace')
            resource_id: The resource identifier
            subject_type: The type of subject ('group' or 'user')
            subject_id: The subject identifier (UUID)
            role_ids: List of role UUIDs to assign

        Returns:
            UpdateRoleBindingResult with the updated binding information

        Raises:
            UnsupportedSubjectTypeError: If the subject type is not supported
            NotFoundError: If the subject or resource cannot be found
            InvalidFieldError: If one or more roles cannot be found
        """
        self._validate_resource(resource_type, resource_id)

        roles = self._get_roles(role_ids)

        subject = self.subject_service.get_subject(subject_type, subject_id)

        RoleBinding.set_roles_for_subject(
            tenant=self.tenant,
            resource_type=resource_type,
            resource_id=resource_id,
            subject=subject,
            roles=roles,
        )

        result = UpdateRoleBindingResult(
            subject_type=subject_type,
            roles=roles,
            resource_id=resource_id,
            resource_type=resource_type,
            subject=subject,
        )

        logger.info(
            "Updated role bindings for %s '%s' on %s '%s': %d roles assigned",
            subject_type,
            subject_id,
            resource_type,
            resource_id,
            len(roles),
        )

        return result

    def _validate_resource(self, resource_type: str, resource_id: str) -> None:
        """Validate that the resource exists.

        Args:
            resource_type: The type of resource
            resource_id: The resource identifier

        Raises:
            RequiredFieldError: If resource_id is empty
            NotFoundError: If the resource cannot be found
        """
        if not resource_id:
            raise RequiredFieldError("resource_id")

        if resource_type == "workspace":
            if not Workspace.objects.filter(id=resource_id, tenant=self.tenant).exists():
                raise NotFoundError(resource_type, resource_id)

    def _get_roles(self, role_ids: list[str]) -> list[RoleV2]:
        """Get roles by their UUIDs, validating all exist."""
        roles = self.role_service.get_assignable_roles(role_ids)

        found_ids = {str(r.uuid) for r in roles}
        requested_ids = set(role_ids)

        if found_ids != requested_ids:
            missing = list(requested_ids - found_ids)
            raise InvalidFieldError("roles", f"The following roles do not exist: {', '.join(missing)}")

        return roles
