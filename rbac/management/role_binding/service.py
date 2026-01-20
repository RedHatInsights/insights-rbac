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
from typing import Optional

from django.db import transaction
from django.db.models import Max, Prefetch, Q, QuerySet
from django.db.models.aggregates import Count
from management.group.model import Group
from management.group.platform import DefaultGroupNotAvailableError, GlobalPolicyIdService
from management.permission.scope_service import Scope
from management.principal.model import Principal
from management.role.platform import platform_v2_role_uuid_for
from management.role.v2_model import PlatformRoleV2, RoleBinding, RoleBindingGroup
from management.tenant_mapping.model import DefaultAccessType, TenantMapping
from management.workspace.model import Workspace

from api.models import Tenant


logger = logging.getLogger(__name__)


class RoleBindingService:
    """Service for role binding queries and operations."""

    def __init__(self, tenant: Tenant):
        """Initialize the service with a tenant."""
        self.tenant = tenant

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
        # Ensure default bindings exist (lazy creation)
        self._ensure_default_bindings_exist()

        # Build base queryset for the specified resource
        queryset = self._build_base_queryset(params["resource_id"], params["resource_type"])

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

    def _build_base_queryset(self, resource_id: str, resource_type: str) -> QuerySet:
        """Build base queryset of groups with role bindings for a resource.

        Args:
            resource_id: The resource identifier
            resource_type: The type of resource

        Returns:
            Annotated QuerySet of Group objects
        """
        # Get groups that have bindings to the specified resource.
        # This includes tenant-specific groups and public tenant default groups.
        # No tenant filter needed since resource_id is tenant-specific.
        queryset = Group.objects.filter(
            role_binding_entries__binding__resource_type=resource_type,
            role_binding_entries__binding__resource_id=resource_id,
        ).distinct()

        # Annotate with principal count
        queryset = queryset.annotate(
            principalCount=Count("principals", filter=Q(principals__type=Principal.Types.USER), distinct=True)
        )

        # Prefetch role bindings for this resource with their roles
        binding_queryset = RoleBinding.objects.filter(
            resource_type=resource_type, resource_id=resource_id
        ).select_related("role")

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
            # Currently only 'group' subject type is supported
            if subject_type != "group":
                # Filter out all results for unsupported subject types
                return queryset.none()

        if subject_id:
            queryset = queryset.filter(uuid=subject_id)

        return queryset

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
        # If all 3 ADMIN bindings exist, default bindings have been processed for this tenant
        admin_binding_uuids = [mapping.default_role_binding_uuid_for(DefaultAccessType.ADMIN, s) for s in Scope]
        existing_admin_count = RoleBinding.objects.filter(uuid__in=admin_binding_uuids).count()

        if existing_admin_count == 3:
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
