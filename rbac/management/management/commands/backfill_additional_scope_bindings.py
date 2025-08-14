"""
Backfill additional scope bindings for existing tenants.

This command:
1. Creates additional role bindings for both default and admin groups
   based on the four policy UUID settings:
   - ROOT_SCOPE_POLICY_UUID (default group → root workspace)
   - TENANT_SCOPE_POLICY_UUID (default group → tenant)
   - ROOT_SCOPE_ADMIN_POLICY_UUID (admin group → root workspace)
   - TENANT_SCOPE_ADMIN_POLICY_UUID (admin group → tenant)

   Note: Default group bindings are skipped for tenants that have custom
   platform default groups, but admin group bindings are still created.

2. Updates system role parent relationships based on permission scope:
   - Roles with tenant-level permissions → parent to tenant scope policies
   - Roles with root-level permissions → parent to root scope policies
   - Default roles → parent to default scope policies

It is idempotent; existing tuples will be skipped.
"""

from typing import List, Optional

from django.conf import settings
from django.core.management.base import BaseCommand
from kessel.relations.v1beta1 import common_pb2
from management.group.model import Group
from management.permission_scope import (
    Scope,
    _implicit_resource_service as permission_service,
)
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    PartitionKey,
    ReplicationEvent,
    ReplicationEventType,
)
from management.role.model import Role
from management.tenant_mapping.model import TenantMapping
from management.workspace.model import Workspace
from migration_tool.models import cleanNameForV2SchemaCompatibility
from migration_tool.utils import create_relationship

from api.models import Tenant


def chunked(iterable, size):
    """Yield successive chunks of size from an iterable."""
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


class Command(BaseCommand):
    """Backfill additional scope role bindings for default and admin groups."""

    help = "Backfill additional scope role bindings for default and admin groups"

    def add_arguments(self, parser):
        """Define CLI arguments for the management command."""
        parser.add_argument("--batch_size", type=int, default=200)
        parser.add_argument("--org_ids", nargs="*", help="Optional list of org_ids to limit backfill")

    def handle(self, *args, **options):
        """Execute the backfill logic over tenants in batches."""
        batch_size: int = options["batch_size"]
        org_ids: Optional[List[str]] = options.get("org_ids") or None

        root_policy = getattr(settings, "ROOT_SCOPE_POLICY_UUID", None) or None
        tenant_policy = getattr(settings, "TENANT_SCOPE_POLICY_UUID", None) or None
        root_admin_policy = getattr(settings, "ROOT_SCOPE_ADMIN_POLICY_UUID", None) or None
        tenant_admin_policy = getattr(settings, "TENANT_SCOPE_ADMIN_POLICY_UUID", None) or None

        if not any([root_policy, tenant_policy, root_admin_policy, tenant_admin_policy]):
            self.stdout.write(self.style.WARNING("No additional scope policy UUIDs configured; nothing to do."))
            return

        replicator = OutboxReplicator()
        partition_key = PartitionKey.byEnvironment()

        tenants = Tenant.objects.exclude(tenant_name="public")
        if org_ids:
            tenants = tenants.filter(org_id__in=org_ids)

        for tenant_batch in chunked(tenants.iterator(), batch_size):
            add: List[common_pb2.Relationship] = []

            for tenant in tenant_batch:
                try:
                    mapping = TenantMapping.objects.get(tenant=tenant)
                except TenantMapping.DoesNotExist:
                    continue

                # Resolve workspaces
                root_ws = Workspace.objects.root(tenant=tenant)

                # Check if tenant has custom platform default groups
                has_custom_default_group = Group.platform_default_set().filter(tenant=tenant).exists()

                # Default group bindings (skip if tenant has custom default group)
                if not has_custom_default_group:
                    if root_policy and root_ws is not None:
                        add.extend(
                            self._binding_tuples(
                                ("rbac", "workspace"),
                                str(root_ws.id),
                                str(mapping.root_scope_role_binding_uuid),
                                root_policy,
                                str(mapping.default_group_uuid),
                            )
                        )
                    if tenant_policy:
                        tenant_res_id = f"{settings.PRINCIPAL_USER_DOMAIN}/{tenant.org_id}"
                        add.extend(
                            self._binding_tuples(
                                ("rbac", "tenant"),
                                tenant_res_id,
                                str(mapping.tenant_scope_role_binding_uuid),
                                tenant_policy,
                                str(mapping.default_group_uuid),
                            )
                        )
                else:
                    self.stdout.write(
                        self.style.WARNING(
                            f"Skipping default group bindings for tenant {tenant.org_id} "
                            f"with custom platform default group"
                        )
                    )

                # Admin group bindings
                if root_admin_policy and root_ws is not None:
                    add.extend(
                        self._binding_tuples(
                            ("rbac", "workspace"),
                            str(root_ws.id),
                            str(mapping.root_scope_admin_role_binding_uuid),
                            root_admin_policy,
                            str(mapping.default_admin_group_uuid),
                        )
                    )
                if tenant_admin_policy:
                    tenant_res_id = f"{settings.PRINCIPAL_USER_DOMAIN}/{tenant.org_id}"
                    add.extend(
                        self._binding_tuples(
                            ("rbac", "tenant"),
                            tenant_res_id,
                            str(mapping.tenant_scope_admin_role_binding_uuid),
                            tenant_admin_policy,
                            str(mapping.default_admin_group_uuid),
                        )
                    )

            if add:
                replicator.replicate(
                    ReplicationEvent(
                        event_type=ReplicationEventType.MIGRATE_SYSTEM_ROLE_ASSIGNMENT,
                        info={"reason": "backfill_additional_scope_bindings"},
                        partition_key=partition_key,
                        add=add,
                        remove=[],
                    )
                )

        # Update system role parent relationships based on permission scope
        self._backfill_system_role_parents()

        self.stdout.write(self.style.SUCCESS("Backfill completed"))

    def _backfill_system_role_parents(self):
        """Update system role parent relationships based on permission scope."""
        # Get policy UUIDs for scope-based parent roles
        platform_default_policy_uuid = getattr(settings, "PLATFORM_DEFAULT_POLICY_UUID", None)
        admin_default_policy_uuid = getattr(settings, "ADMIN_DEFAULT_POLICY_UUID", None)
        root_scope_policy_uuid = getattr(settings, "ROOT_SCOPE_POLICY_UUID", None)
        tenant_scope_policy_uuid = getattr(settings, "TENANT_SCOPE_POLICY_UUID", None)
        root_scope_admin_policy_uuid = getattr(settings, "ROOT_SCOPE_ADMIN_POLICY_UUID", None)
        tenant_scope_admin_policy_uuid = getattr(settings, "TENANT_SCOPE_ADMIN_POLICY_UUID", None)

        if not any(
            [
                root_scope_policy_uuid,
                tenant_scope_policy_uuid,
                root_scope_admin_policy_uuid,
                tenant_scope_admin_policy_uuid,
            ]
        ):
            self.stdout.write(
                self.style.WARNING("No scope-specific policy UUIDs configured; skipping system role parent updates.")
            )
            return

        replicator = OutboxReplicator()
        partition_key = PartitionKey.byEnvironment()

        # Get all system roles
        system_roles = Role.objects.filter(system=True).prefetch_related("access__permission")

        add: List[common_pb2.Relationship] = []
        remove: List[common_pb2.Relationship] = []

        for role in system_roles:
            # Get v1 and v2 permissions for the role
            v1_permissions: List[str] = []
            v2_permissions: List[str] = []
            for access in role.access.all():
                v1_perm = access.permission
                v1_perm_string = v1_perm.permission  # This is already "app:resource_type:verb"
                v2_perm = cleanNameForV2SchemaCompatibility(v1_perm_string)
                v1_permissions.append(v1_perm_string)
                v2_permissions.append(v2_perm)

            if not v1_permissions:
                continue

            # Determine highest scope for the role's permissions using V1 permissions
            # (scope settings are configured to match V1 permission format)
            highest_scope: Scope = permission_service.highest_scope_for_permissions(v1_permissions)

            # Map scope to policy parents
            def platform_parent_for_scope(scope: Scope) -> Optional[str]:
                if scope == Scope.TENANT:
                    return tenant_scope_policy_uuid
                if scope == Scope.ROOT:
                    return root_scope_policy_uuid
                return platform_default_policy_uuid

            def admin_parent_for_scope(scope: Scope) -> Optional[str]:
                if scope == Scope.TENANT:
                    return tenant_scope_admin_policy_uuid
                if scope == Scope.ROOT:
                    return root_scope_admin_policy_uuid
                return admin_default_policy_uuid

            # Remove old parent relationships (if they exist)
            if role.platform_default and platform_default_policy_uuid:
                remove.append(
                    create_relationship(
                        ("rbac", "role"), platform_default_policy_uuid, ("rbac", "role"), str(role.uuid), "child"
                    )
                )
            if role.admin_default and admin_default_policy_uuid:
                remove.append(
                    create_relationship(
                        ("rbac", "role"), admin_default_policy_uuid, ("rbac", "role"), str(role.uuid), "child"
                    )
                )

            # Add new scope-based parent relationships
            if role.platform_default:
                parent_uuid = platform_parent_for_scope(highest_scope)
                if parent_uuid:
                    add.append(
                        create_relationship(("rbac", "role"), parent_uuid, ("rbac", "role"), str(role.uuid), "child")
                    )

            if role.admin_default:
                parent_uuid = admin_parent_for_scope(highest_scope)
                if parent_uuid:
                    add.append(
                        create_relationship(("rbac", "role"), parent_uuid, ("rbac", "role"), str(role.uuid), "child")
                    )

        if add or remove:
            replicator.replicate(
                ReplicationEvent(
                    event_type=ReplicationEventType.MIGRATE_SYSTEM_ROLE_ASSIGNMENT,
                    info={"reason": "backfill_system_role_parents"},
                    partition_key=partition_key,
                    add=add,
                    remove=remove,
                )
            )
            self.stdout.write(self.style.SUCCESS(f"Updated parent relationships for {len(system_roles)} system roles"))

    def _binding_tuples(
        self,
        resource_type: tuple[str, str],
        resource_id: str,
        role_binding_uuid: str,
        policy_uuid: str,
        group_uuid: str,
    ) -> list[common_pb2.Relationship]:
        return [
            create_relationship(
                (resource_type[0], resource_type[1]),
                resource_id,
                ("rbac", "role_binding"),
                role_binding_uuid,
                "binding",
            ),
            create_relationship(("rbac", "role_binding"), role_binding_uuid, ("rbac", "role"), policy_uuid, "role"),
            create_relationship(
                ("rbac", "role_binding"), role_binding_uuid, ("rbac", "group"), group_uuid, "subject", "member"
            ),
        ]
