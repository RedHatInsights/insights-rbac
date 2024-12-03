"""V2 implementation of Tenant bootstrapping."""

from typing import List, Optional
from uuid import UUID

from django.conf import settings
from django.db.models import Prefetch, Q
from kessel.relations.v1beta1.common_pb2 import Relationship
from management.group.model import Group
from management.principal.model import Principal
from management.relation_replicator.relation_replicator import (
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.tenant_mapping.model import TenantMapping, logger
from management.tenant_service.tenant_service import BootstrappedTenant
from management.tenant_service.tenant_service import _ensure_principal_with_user_id_in_tenant
from management.workspace.model import Workspace
from migration_tool.utils import create_relationship


from api.models import Tenant, User


class V2TenantBootstrapService:
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

    def new_bootstrapped_tenant(self, org_id: str, account_number: Optional[str] = None) -> BootstrappedTenant:
        """Create a new tenant."""
        tenant = Tenant.objects.create(org_id=org_id, account_id=account_number)
        return self._bootstrap_tenant(tenant)

    def bootstrap_tenant(self, tenant: Tenant, force: bool = False) -> BootstrappedTenant:
        """
        Bootstrap an existing tenant.

        If [force] is True, will re-bootstrap the tenant if already bootstrapped.
        This does not change the RBAC data that already exists, but will replicate to Relations.
        """
        try:
            mapping = TenantMapping.objects.get(tenant=tenant)
            if force:
                self._replicate_bootstrap(tenant, mapping)
            return BootstrappedTenant(tenant=tenant, mapping=mapping)
        except TenantMapping.DoesNotExist:
            return self._bootstrap_tenant(tenant)

    def update_user(
        self,
        user: User,
        upsert: bool = False,
        bootstrapped_tenant: Optional[BootstrappedTenant] = None,
        ready_tenant: bool = True,
    ) -> Optional[BootstrappedTenant]:
        """
        Bootstrap a user in a tenant.

        Create a Tenant (and bootstrap it) if it does not exist.
        If a [bootstrapped_tenant] is provided, it's assumed the Tenant already exists.

        Creates a [Principal] for the [user] if [upsert] is True. Otherwise,
        only updates the [Principal] with the user's user_id if needed.

        Returns [None] if the user is not active.
        """
        if user.org_id is None:
            raise ValueError(f"Cannot update user without org_id. username={user.username}")

        if not user.is_active:
            self._disable_user_in_tenant(user)
            return None

        bootstrapped_tenant = bootstrapped_tenant or self._get_or_bootstrap_tenant(
            user.org_id, ready_tenant, user.account
        )
        mapping = bootstrapped_tenant.mapping
        if mapping is None:
            raise ValueError(f"Expected TenantMapping but got None. org_id: {bootstrapped_tenant.tenant.org_id}")

        user_id = user.user_id

        if user_id is None:
            raise ValueError(f"Cannot update user without user_id. username={user.username}")

        tuples_to_add = []
        tuples_to_remove = []

        # Add user to default group if not a service account
        if not user.is_service_account:
            _ensure_principal_with_user_id_in_tenant(user, bootstrapped_tenant.tenant, upsert=upsert)
            tuples_to_add, tuples_to_remove = self._default_group_tuple_edits(user, mapping)

        self._replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.EXTERNAL_USER_UPDATE,
                info={"user_id": user_id},
                partition_key=PartitionKey.byEnvironment(),
                add=tuples_to_add,
                remove=tuples_to_remove,
            )
        )

        return bootstrapped_tenant

    def import_bulk_users(self, users: list[User], ready_tenants: bool = False):
        """
        Bootstrap multiple users in a tenant.

        Create each users' Tenant (and bootstrap it) if it does not exist.
        Updates each [Principal] with the user's user_id if Principal exists but user_id not set.

        Args:
            users (list): List of User objects to update
        """
        org_ids = set()
        for user in users:
            if not user.is_active:
                logger.info(f"User is not active. Skipping import. user_id={user.user_id} org_id={user.org_id}")
                continue
            if user.org_id is None:
                logger.warning(f"Cannot update user without org_id. Skipping. username={user.username}")
                continue
            org_ids.add(user.org_id)
        bootstrapped_list = self._get_or_bootstrap_tenants(org_ids, ready_tenants)
        bootstrapped_mapping = {bootstrapped.tenant.org_id: bootstrapped for bootstrapped in bootstrapped_list}

        tuples_to_add = []
        tuples_to_remove = []
        principals_to_update = []

        # Fetch existing principals
        tenants = [bootstrapped.tenant for bootstrapped in bootstrapped_list]
        existing_principals = (
            Principal.objects.filter(Q(tenant__in=tenants) & Q(username__in=[user.username for user in users]))
            .order_by()  # remove default sort order
            .prefetch_related("tenant")
        )
        # Mapping of (org_id, username) -> principal
        existing_principal_dict = {(p.tenant.org_id, p.username): p for p in existing_principals}

        for user in users:
            if not user.is_active:
                continue
            if user.org_id is None:
                logger.warning(f"Cannot update user without org_id. Skipping. username={user.username}")
                continue
            bootstrapped = bootstrapped_mapping[user.org_id]
            key = (user.org_id, user.username)
            user_id = user.user_id
            if key in existing_principal_dict:  # Principal already in rbac db
                principal = existing_principal_dict[key]
                if principal.user_id != user_id:
                    principal.user_id = user_id
                    principals_to_update.append(principal)

            mapping = bootstrapped.mapping
            if mapping is None:
                raise ValueError(f"Expected TenantMapping but got None. org_id: {bootstrapped.tenant.org_id}")

            sub_tuples_to_add, sub_tuples_to_remove = self._default_group_tuple_edits(user, mapping)
            tuples_to_add.extend(sub_tuples_to_add)
            tuples_to_remove.extend(sub_tuples_to_remove)
        # Bulk update existing principals
        if principals_to_update:
            Principal.objects.bulk_update(principals_to_update, ["user_id"])

        self._replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.BULK_EXTERNAL_USER_UPDATE,
                info={"num_users": len(users), "first_user_id": users[0].user_id if users else None},
                partition_key=PartitionKey.byEnvironment(),
                add=tuples_to_add,
                remove=tuples_to_remove,
            )
        )

    def _disable_user_in_tenant(self, user: User):
        """Disable a user in a tenant."""
        assert not user.is_active

        # Get tenant mapping if present but no need to create if not
        tuples_to_remove = []
        user_id = user.user_id

        if user_id is None:
            raise ValueError(f"User {user.username} has no user_id.")

        try:
            mapping = TenantMapping.objects.filter(tenant__org_id=user.org_id).get()
            tuples_to_remove.append(Group.relationship_to_user_id_for_group(str(mapping.default_group_uuid), user_id))
        except TenantMapping.DoesNotExist:
            pass

        try:
            principal = Principal.objects.filter(username=user.username, tenant__org_id=user.org_id).get()

            for group in principal.group.all():
                group.principals.remove(principal)
                tuples_to_remove.append(group.relationship_to_principal(principal))

            principal.delete()
        except Principal.DoesNotExist:
            pass

        self._replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.EXTERNAL_USER_UPDATE,
                info={"user_id": user_id},
                partition_key=PartitionKey.byEnvironment(),
                remove=tuples_to_remove,
            )
        )

    def _get_or_bootstrap_tenant(
        self, org_id: str, ready: bool, account_number: Optional[str] = None
    ) -> BootstrappedTenant:
        tenant_name = f"org{org_id}"
        tenant, _ = Tenant.objects.get_or_create(
            org_id=org_id,
            defaults={"ready": ready, "account_id": account_number, "tenant_name": tenant_name},
        )
        try:
            mapping = TenantMapping.objects.get(tenant=tenant)
            logger.info(f"Tenant already bootstrapped. org_id={tenant.org_id}")
            return BootstrappedTenant(
                tenant=tenant,
                mapping=mapping,
            )
        except TenantMapping.DoesNotExist:
            bootstrap = self._bootstrap_tenant(tenant)
            return bootstrap

    def _bootstrap_tenant(self, tenant: Tenant) -> BootstrappedTenant:
        if tenant.tenant_name == "public":
            raise ValueError("Cannot bootstrap public tenant.")

        # Set up workspace hierarchy for Tenant
        root_workspace, default_workspace, relationships = self._built_in_workspaces(tenant)
        root_workspace.save(force_insert=True)
        default_workspace.save(force_insert=True)

        # We do not check for custom default group here.
        # By this point if there is a custom default group,
        # a TenantMapping must have already been created.
        mapping = TenantMapping.objects.create(tenant=tenant)
        relationships.extend(self._bootstrap_default_access(tenant, mapping, str(default_workspace.id)))

        self._replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.BOOTSTRAP_TENANT,
                info={"org_id": tenant.org_id, "default_workspace_id": str(default_workspace.id)},
                partition_key=PartitionKey.byEnvironment(),
                add=relationships,
            )
        )

        return BootstrappedTenant(tenant, mapping, default_workspace=default_workspace, root_workspace=root_workspace)

    def _replicate_bootstrap(self, tenant: Tenant, mapping: TenantMapping):
        """Replicate the bootstrapping of a tenant."""
        built_in_workspaces = Workspace.objects.filter(
            tenant=tenant, type__in=[Workspace.Types.ROOT, Workspace.Types.DEFAULT]
        )
        root = next(ws for ws in built_in_workspaces if ws.type == Workspace.Types.ROOT)
        default = next(ws for ws in built_in_workspaces if ws.type == Workspace.Types.DEFAULT)

        relationships = []
        relationships.extend(self._built_in_hierarchy_tuples(default.id, root.id, tenant.org_id))
        relationships.extend(self._bootstrap_default_access(tenant, mapping, str(default.id)))

        self._replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.BOOTSTRAP_TENANT,
                info={"org_id": tenant.org_id, "internal": True},
                partition_key=PartitionKey.byEnvironment(),
                add=relationships,
            )
        )

    def _get_or_bootstrap_tenants(self, org_ids: set, ready: bool) -> list[BootstrappedTenant]:
        """Bootstrap list of tenants, used by import_bulk_users."""
        # Fetch existing tenants
        existing_tenants = {
            tenant.org_id: tenant
            for tenant in Tenant.objects.filter(org_id__in=org_ids)
            .select_related("tenant_mapping")
            .prefetch_related(
                Prefetch(
                    "group_set",
                    queryset=Group.objects.filter(platform_default=True).order_by(),
                    to_attr="platform_default_groups",
                )
            )
        }

        # An existing tenant might have been bootstrapped and already has mapping and workspaces
        tenants_to_bootstrap: list[Tenant] = []
        bootstrapped_list: list[BootstrappedTenant] = []
        for tenant in existing_tenants.values():
            if not hasattr(tenant, "tenant_mapping"):
                tenants_to_bootstrap.append(tenant)
            else:
                logger.info(f"Tenant already bootstrapped. org_id={tenant.org_id}")
                bootstrapped_list.append(BootstrappedTenant(tenant, tenant.tenant_mapping))
        # Create new tenants
        new_tenants = [
            Tenant(tenant_name=f"org{org_id}", org_id=org_id, ready=ready)
            for org_id in org_ids
            if org_id not in existing_tenants
        ]
        if new_tenants:
            new_tenants = Tenant.objects.bulk_create(new_tenants)
            tenants_to_bootstrap.extend(new_tenants)
        if tenants_to_bootstrap:
            bootstrapped_list.extend(self._bootstrap_tenants(tenants_to_bootstrap))
        return bootstrapped_list

    def _bootstrap_tenants(self, tenants: list[Tenant]) -> list[BootstrappedTenant]:
        # Set up workspace hierarchy for Tenant
        workspaces: list[Workspace] = []
        relationships: list[Relationship] = []
        mappings_to_create: list[TenantMapping] = []
        default_workspace_ids: list[UUID] = []
        for tenant in tenants:
            kwargs = {"tenant": tenant}
            if hasattr(tenant, "platform_default_groups") and tenant.platform_default_groups:
                group_uuid = tenant.platform_default_groups[0].uuid
                logger.info(f"Using custom default group for tenant. org_id={tenant.org_id} group_uuid={group_uuid}")
                kwargs["default_group_uuid"] = group_uuid
            mappings_to_create.append(TenantMapping(**kwargs))

            root, default, built_in_relationships = self._built_in_workspaces(tenant)

            default_workspace_ids.append(default.id)
            workspaces.extend([root, default])
            relationships.extend(built_in_relationships)

        Workspace.objects.bulk_create(workspaces)

        mappings = TenantMapping.objects.bulk_create(mappings_to_create)
        tenant_mappings = {mapping.tenant_id: mapping for mapping in mappings}
        bootstrapped_tenants = []

        for tenant, default_workspace_id in zip(tenants, default_workspace_ids):
            mapping = tenant_mappings[tenant.id]
            relationships.extend(self._bootstrap_default_access(tenant, mapping, str(default_workspace_id)))
            bootstrapped_tenants.append(BootstrappedTenant(tenant, mapping))
        self._replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.BULK_BOOTSTRAP_TENANT,
                info={"num_tenants": len(tenants), "first_org_id": tenants[0].org_id if tenants else None},
                partition_key=PartitionKey.byEnvironment(),
                add=relationships,
            )
        )
        return bootstrapped_tenants

    def _default_group_tuple_edits(self, user: User, mapping) -> tuple[list[Relationship], list[Relationship]]:
        """Get the tuples to add and remove for a user."""
        tuples_to_add = []
        tuples_to_remove = []
        user_id = user.user_id

        if user_id is None:
            raise ValueError(f"User {user.username} has no user_id.")

        tuples_to_add.append(Group.relationship_to_user_id_for_group(str(mapping.default_group_uuid), user_id))

        # Add user to admin group if admin
        if user.admin:
            tuples_to_add.append(
                Group.relationship_to_user_id_for_group(str(mapping.default_admin_group_uuid), user_id)
            )
        else:
            # If not admin, ensure they are not in the admin group
            # (we don't know what the previous state was)
            tuples_to_remove.append(
                Group.relationship_to_user_id_for_group(str(mapping.default_admin_group_uuid), user_id)
            )

        return tuples_to_add, tuples_to_remove

    def _built_in_hierarchy_tuples(self, default_workspace_id, root_workspace_id, org_id) -> List[Relationship]:
        """Create the tuples used to bootstrap the hierarchy of default->root->tenant->platform."""
        tenant_id = f"{self._user_domain}/{org_id}"

        return [
            create_relationship(
                ("rbac", "workspace"),
                str(default_workspace_id),
                ("rbac", "workspace"),
                str(root_workspace_id),
                "parent",
            ),
            create_relationship(
                ("rbac", "workspace"), str(root_workspace_id), ("rbac", "tenant"), tenant_id, "parent"
            ),
            # Include platform for tenant
            create_relationship(("rbac", "tenant"), tenant_id, ("rbac", "platform"), settings.ENV_NAME, "platform"),
        ]

    def _default_binding_tuples(
        self, default_workspace_id, role_binding_uuid, default_role_uuid, default_group_uuid
    ) -> List[Relationship]:
        """
        Create the tuples used to bootstrap default access for a Workspace.

        Can be used for both default access and admin access as long as the correct arguments are provided.
        Each of role binding, role, and group must refer to admin or default versions.
        """
        return [
            create_relationship(
                ("rbac", "workspace"),
                default_workspace_id,
                ("rbac", "role_binding"),
                role_binding_uuid,
                "binding",
            ),
            create_relationship(
                ("rbac", "role_binding"),
                role_binding_uuid,
                ("rbac", "role"),
                default_role_uuid,
                "role",
            ),
            create_relationship(
                ("rbac", "role_binding"),
                role_binding_uuid,
                ("rbac", "group"),
                default_group_uuid,
                "subject",
                "member",
            ),
        ]

    def _bootstrap_default_access(
        self, tenant: Tenant, mapping: TenantMapping, default_workspace_id: str
    ) -> List[Relationship]:
        """
        Bootstrap default access for a tenant's users and admins.

        Creates role bindings between the tenant's default workspace, default groups, and system policies.
        """
        platform_default_role_uuid = self._get_platform_default_policy_uuid()
        admin_default_role_uuid = self._get_admin_default_policy_uuid()

        if platform_default_role_uuid is None:
            logger.warning("No platform default role found for public tenant. Default access will not be set up.")

        if admin_default_role_uuid is None:
            logger.warning("No admin default role found for public tenant. Default access will not be set up.")

        default_user_role_binding_uuid = str(mapping.default_role_binding_uuid)
        default_admin_role_binding_uuid = str(mapping.default_admin_role_binding_uuid)

        tuples_to_add: List[Relationship] = []

        # Add default role binding IFF there is no custom default access for the tenant

        # NOTE: This logic is prone to write skew: the platform group for the tenant may be created concurrently.
        # Care must be taken to prevent this.
        # Currently, when this default group is created (in group/definer.py) we:
        # 1. Check for the existence of a tenant mapping. If exists, use that.
        #    No race because if it already exists, this process must've already happened.
        # 2. If tenant mapping does not exist, create it via this same bootstrap process.
        #    Due to unique constraint, if this happens concurrently from another input (e.g. user import),
        #    one will rollback, serializing the group creation with user import on next retry.
        if platform_default_role_uuid and not (
            hasattr(tenant, "platform_default_groups") and tenant.platform_default_groups
        ):
            tuples_to_add.extend(
                self._default_binding_tuples(
                    default_workspace_id,
                    default_user_role_binding_uuid,
                    platform_default_role_uuid,
                    str(mapping.default_group_uuid),
                )
            )
        else:
            logger.info(
                f"Not setting up default access for tenant with customized default group. org_id={tenant.org_id}"
            )

        # Admin role binding is not customizable
        if admin_default_role_uuid:
            tuples_to_add.extend(
                self._default_binding_tuples(
                    default_workspace_id,
                    default_admin_role_binding_uuid,
                    admin_default_role_uuid,
                    str(mapping.default_admin_group_uuid),
                )
            )
        return tuples_to_add

    def _built_in_workspaces(self, tenant: Tenant) -> tuple[Workspace, Workspace, list[Relationship]]:
        relationships = []

        root = Workspace(tenant=tenant, type=Workspace.Types.ROOT, name="Root Workspace")
        default = Workspace(
            parent_id=root.id,
            tenant=tenant,
            type=Workspace.Types.DEFAULT,
            name="Default Workspace",
        )

        root_workspace_id = root.id
        default_workspace_id = default.id

        relationships.extend(self._built_in_hierarchy_tuples(default_workspace_id, root_workspace_id, tenant.org_id))

        return root, default, relationships

    def _get_platform_default_policy_uuid(self) -> Optional[str]:
        try:
            if self._platform_default_policy_uuid is None:
                policy = Group.objects.get(
                    platform_default=True, system=True, tenant=self._get_public_tenant()
                ).policies.get()
                self._platform_default_policy_uuid = str(policy.uuid)
            return self._platform_default_policy_uuid
        except Group.DoesNotExist:
            return None

    def _get_admin_default_policy_uuid(self) -> Optional[str]:
        try:
            if self._admin_default_policy_uuid is None:
                policy = Group.objects.get(
                    admin_default=True, system=True, tenant=self._get_public_tenant()
                ).policies.get()
                self._admin_default_policy_uuid = str(policy.uuid)
            return self._admin_default_policy_uuid
        except Group.DoesNotExist:
            return None

    def _get_public_tenant(self) -> Tenant:
        if self._public_tenant is None:
            self._public_tenant = Tenant.objects.get(tenant_name="public")
        return self._public_tenant
