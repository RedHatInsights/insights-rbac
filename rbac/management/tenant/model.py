"""Additional tenant-related models."""

import uuid
from typing import List, Optional
from typing import NamedTuple

from django.conf import settings
from django.db import models, transaction
from kessel.relations.v1beta1.common_pb2 import Relationship
from management.group.model import Group
from management.principal.model import Principal
from management.role.relation_api_dual_write_handler import RelationReplicator, ReplicationEvent, ReplicationEventType
from management.workspace.model import Workspace
from migration_tool.utils import create_relationship

from api.models import Tenant, User


class TenantMapping(models.Model):
    """Tenant mappings to V2 domain concepts."""

    tenant = models.OneToOneField(Tenant, on_delete=models.CASCADE)
    default_group_uuid = models.UUIDField(default=uuid.uuid4, editable=False, null=False)
    default_admin_group_uuid = models.UUIDField(default=uuid.uuid4, editable=False, null=False)
    default_user_role_binding_uuid = models.UUIDField(default=uuid.uuid4, editable=False, null=False)
    default_admin_role_binding_uuid = models.UUIDField(default=uuid.uuid4, editable=False, null=False)


class BootstrappedTenant(NamedTuple):
    """Tenant information."""

    tenant: Tenant
    root_workspace: Workspace
    default_workspace: Workspace
    mapping: TenantMapping
    tuples: List[Relationship]  # TODO: maybe remove this


class TenantBootstrapService:
    """Service for bootstrapping tenants with built-in relationships."""

    _replicator: RelationReplicator
    _user_domain = settings.PRINCIPAL_USER_DOMAIN
    _public_tenant: Optional[Tenant]
    _platform_default_policy_uuid: Optional[str] = None
    _admin_default_policy_uuid: Optional[str] = None

    def __init__(self, replicator: RelationReplicator, public_tenant: Optional[Tenant] = None):
        """Initialize the TenantBootstrapService with a RelationReplicator."""
        self._replicator = replicator
        self._public_tenant = public_tenant

    def new_bootstrapped_tenant(self) -> BootstrappedTenant:
        """Create a new tenant."""
        tenant = Tenant.objects.create()
        return self.bootstrap_tenant(tenant)

    @transaction.atomic
    def get_or_bootstrap_tenant(self, org_id: str, account_number: Optional[str] = None) -> BootstrappedTenant:
        """Get or create a tenant and replicate relations for it in a single transaction."""
        return self._get_or_bootstrap_tenant(org_id, account_number)

    @transaction.atomic
    def bootstrap_tenant(
        self,
        tenant: Tenant,
    ) -> BootstrappedTenant:
        """
        Bootstrap a tenant with built-in workspaces, default groups, and default role bindings.

        Replicates related tuples with writes in a single transaction.
        """
        return self._bootstrap_tenant(tenant)

    @transaction.atomic
    def update_user(self, user: User, bootstrapped_tenant: Optional[BootstrappedTenant] = None):
        """Bootstrap a user in a tenant."""
        if user.is_service_account:
            return

        if not user.is_active:
            self._disable_user_in_tenant(user)
            return

        bootstrapped_tenant = bootstrapped_tenant or self._get_or_bootstrap_tenant(user.org_id, user.account)

        mapping = bootstrapped_tenant.mapping
        # TODO: DRY this? repeated in RelationApiDualWriteGroupHandler
        principal_id = f"{self._user_domain}:{user.user_id}"
        tuples_to_add = []
        tuples_to_remove = []

        # Add user to default group
        self._ensure_principal_with_user_id_in_tenant(user, bootstrapped_tenant.tenant)

        tuples_to_add.append(
            create_relationship(
                ("rbac", "group"),
                mapping.default_group_uuid,
                ("rbac", "principal"),
                principal_id,
                "member",
            )
        )

        # Add user to admin group if admin
        if user.admin:
            tuples_to_add.append(
                create_relationship(
                    ("rbac", "group"),
                    mapping.default_admin_group_uuid,
                    ("rbac", "principal"),
                    principal_id,
                    "member",
                )
            )
        else:
            tuples_to_remove.append(
                create_relationship(
                    ("rbac", "group"),
                    mapping.default_admin_group_uuid,
                    ("rbac", "principal"),
                    principal_id,
                    "member",
                )
            )

        self._replicator.replicate(
            ReplicationEvent(
                type=ReplicationEventType.EXTERNAL_USER_UPDATE,
                info={"principal_id": principal_id},
                partition_key="rbactodo",
                add=tuples_to_add,
                remove=tuples_to_remove,
            )
        )

    def _disable_user_in_tenant(self, user: User):
        """Disable a user in a tenant."""
        assert not user.is_active

        # Get tenant mapping if present but no need to create if not
        tuples_to_remove = []
        # TODO: DRY this? repeated in RelationApiDualWriteGroupHandler
        principal_id = f"{self._user_domain}:{user.user_id}"

        try:
            mapping = TenantMapping.objects.filter(tenant__org_id=user.org_id).get()
            tuples_to_remove.append(
                create_relationship(
                    ("rbac", "group"),
                    mapping.default_group_uuid,
                    ("rbac", "principal"),
                    principal_id,
                    "member",
                )
            )
            tuples_to_remove.append(
                create_relationship(
                    ("rbac", "group"),
                    mapping.default_admin_group_uuid,
                    ("rbac", "principal"),
                    principal_id,
                    "member",
                )
            )
        except TenantMapping.DoesNotExist:
            pass

        try:
            principal = Principal.objects.filter(username=user.username, tenant_id=mapping.tenant_id).get()

            for group in principal.group.all():
                group.principals.remove(principal)
                tuples_to_remove.append(
                    create_relationship(
                        ("rbac", "group"),
                        group.uuid,
                        ("rbac", "principal"),
                        principal_id,
                        "member",
                    )
                )

            principal.delete()
        except Principal.DoesNotExist:
            pass

        self._replicator.replicate(
            ReplicationEvent(
                type=ReplicationEventType.EXTERNAL_USER_UPDATE,
                info={"principal_id": principal_id},
                partition_key="rbactodo",
                remove=tuples_to_remove,
            )
        )

    def _get_or_bootstrap_tenant(self, org_id: str, account_number: Optional[str] = None) -> BootstrappedTenant:
        tenant_name = f"org{org_id}"
        tenant, _ = Tenant.objects.get_or_create(
            org_id=org_id,
            defaults={"ready": True, "account_id": account_number, "tenant_name": tenant_name},
        )
        bootstrap = self._bootstrap_tenant(tenant)
        self._replicator.replicate(
            ReplicationEvent(
                type=ReplicationEventType.BOOTSTRAP_TENANT,
                info={"org_id": org_id, "default_workspace_uuid": str(bootstrap.default_workspace.uuid)},
                partition_key="rbactodo",
                add=bootstrap.tuples,
            )
        )
        return bootstrap

    def _bootstrap_tenant(self, tenant: Tenant) -> BootstrappedTenant:
        # Set up workspace hierarchy for Tenant
        root_workspace = Workspace.objects.create(
            tenant=tenant,
            type=Workspace.Types.ROOT,
            name="Root Workspace",
        )
        default_workspace = Workspace.objects.create(
            tenant=tenant,
            type=Workspace.Types.DEFAULT,
            parent=root_workspace,
            name="Default Workspace",
        )
        tenant_id = f"{self._user_domain}:{tenant.org_id}"
        relationships = [
            create_relationship(
                ("rbac", "workspace"),
                str(default_workspace.uuid),
                ("rbac", "workspace"),
                str(root_workspace.uuid),
                "parent",
            ),
            create_relationship(
                ("rbac", "workspace"), str(root_workspace.uuid), ("rbac", "tenant"), tenant_id, "parent"
            ),
        ]

        # Include platform for tenant
        relationships.append(
            create_relationship(("rbac", "tenant"), tenant_id, ("rbac", "platform"), settings.ENV_NAME, "platform")
        )

        mapping = TenantMapping.objects.create(tenant=tenant)
        relationships.extend(self._bootstrap_default_access(tenant, mapping, default_workspace))

        return BootstrappedTenant(tenant, root_workspace, default_workspace, mapping, relationships)

    def _bootstrap_default_access(
        self, tenant: Tenant, mapping: TenantMapping, default_workspace: Workspace
    ) -> List[Relationship]:
        """
        Bootstrap default access for a tenant's users and admins.

        Creates role bindings between the tenant's default workspace, default groups, and system policies.
        """
        platform_default_role = self._get_platform_default_policy_uuid()
        admin_default_role = self._get_admin_default_policy_uuid()

        default_workspace_uuid = str(default_workspace.uuid)
        default_user_role_binding_uuid = str(mapping.default_user_role_binding_uuid)
        default_admin_role_binding_uuid = str(mapping.default_admin_role_binding_uuid)

        tuples_to_add: List[Relationship] = []

        # Add default role binding IFF there is no custom default access for the tenant
        if not Group.objects.filter(platform_default=True, tenant=tenant).exists():
            tuples_to_add.extend(
                [
                    create_relationship(
                        ("rbac", "workspace"),
                        default_workspace_uuid,
                        ("rbac", "role_binding"),
                        default_user_role_binding_uuid,
                        "binding",
                    ),
                    create_relationship(
                        ("rbac", "role_binding"),
                        default_user_role_binding_uuid,
                        ("rbac", "role"),
                        platform_default_role,
                        "role",
                    ),
                    create_relationship(
                        ("rbac", "role_binding"),
                        default_user_role_binding_uuid,
                        ("rbac", "group"),
                        str(mapping.default_group_uuid),
                        "group",
                        "member",
                    ),
                ]
            )

        # Admin role binding is not customizable
        tuples_to_add.extend(
            [
                create_relationship(
                    ("rbac", "workspace"),
                    default_workspace_uuid,
                    ("rbac", "role_binding"),
                    default_admin_role_binding_uuid,
                    "binding",
                ),
                create_relationship(
                    ("rbac", "role_binding"),
                    default_admin_role_binding_uuid,
                    ("rbac", "role"),
                    admin_default_role,
                    "role",
                ),
                create_relationship(
                    ("rbac", "role_binding"),
                    default_admin_role_binding_uuid,
                    ("rbac", "group"),
                    str(mapping.default_admin_group_uuid),
                    "group",
                    "member",
                ),
            ]
        )

        return tuples_to_add

    def _get_platform_default_policy_uuid(self) -> str:
        if self._platform_default_policy_uuid is None:
            policy = Group.objects.get(
                platform_default=True, system=True, tenant=self._get_public_tenant()
            ).policies.get()
            self._platform_default_policy_uuid = str(policy.uuid)
        return self._platform_default_policy_uuid

    def _get_admin_default_policy_uuid(self) -> str:
        if self._admin_default_policy_uuid is None:
            policy = Group.objects.get(
                admin_default=True, system=True, tenant=self._get_public_tenant()
            ).policies.get()
            self._admin_default_policy_uuid = str(policy.uuid)
        return self._admin_default_policy_uuid

    def _get_public_tenant(self) -> Tenant:
        if self._public_tenant is None:
            self._public_tenant = Tenant.objects.get(tenant_name="public")
        return self._public_tenant

    def _ensure_principal_with_user_id_in_tenant(self, user: User, tenant: Tenant):
        principal, created = Principal.objects.get_or_create(
            username=user.username,
            tenant=tenant,
            defaults={"user_id": user.user_id},
        )

        if not created and principal.user_id != user.user_id:
            principal.user_id = user.user_id
            principal.save()
