"""V2 implementation of Tenant bootstrapping."""

from typing import Callable, List, Optional
from uuid import UUID

from django.conf import settings
from django.db.models import Prefetch, Q, QuerySet
from kessel.relations.v1beta1.common_pb2 import Relationship
from management.group.model import Group
from management.group.platform import DefaultGroupNotAvailableError, GlobalPolicyIdService
from management.principal.model import Principal
from management.relation_replicator.relation_replicator import (
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.tenant_mapping.model import DefaultAccessType, TenantMapping, logger
from management.tenant_service.relations import default_role_binding_tuples
from management.tenant_service.tenant_service import BootstrappedTenant
from management.tenant_service.tenant_service import _ensure_principal_with_user_id_in_tenant
from management.workspace.model import Workspace
from migration_tool.utils import create_relationship


from api.models import Tenant, User


def default_get_user_id(user: User):
    """Get user ID."""
    if user.user_id is None:
        raise ValueError(f"Cannot update user without user_id. username={user.username}")
    return user.user_id


class V2TenantBootstrapService:
    """Service for bootstrapping tenants with built-in relationships."""

    _replicator: RelationReplicator
    _user_domain = settings.PRINCIPAL_USER_DOMAIN
    _public_tenant: Optional[Tenant]
    _policy_service: GlobalPolicyIdService

    def __init__(
        self,
        replicator: RelationReplicator,
        public_tenant: Optional[Tenant] = None,
        get_user_id: Optional[Callable[[User], str]] = None,
    ):
        """Initialize the TenantBootstrapService with a RelationReplicator."""
        self._replicator = replicator
        self._public_tenant = public_tenant
        self._get_user_id = get_user_id if get_user_id else default_get_user_id
        self._policy_service = GlobalPolicyIdService.shared()

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

    def create_ungrouped_workspace(self, org_id) -> Workspace:
        """Util for creating ungrouped workspace. Can be removed once ungrouped workspace has gone."""
        tenant = Tenant.objects.get(org_id=org_id)
        default = Workspace.objects.get(tenant=tenant, type=Workspace.Types.DEFAULT)
        ungrouped_hosts, _ = Workspace.objects.get_or_create(
            tenant=tenant,
            type=Workspace.Types.UNGROUPED_HOSTS,
            name=Workspace.SpecialNames.UNGROUPED_HOSTS,
            parent=default,
        )

        relationship = create_relationship(
            ("rbac", "workspace"),
            str(ungrouped_hosts.id),
            ("rbac", "workspace"),
            str(default.id),
            "parent",
        )
        self._replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.CREATE_UNGROUPED_HOSTS_WORKSPACE,
                info={"org_id": tenant.org_id, "ungrouped_hosts_id": str(ungrouped_hosts.id)},
                partition_key=PartitionKey.byEnvironment(),
                add=[relationship],
            )
        )
        return ungrouped_hosts

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

        user.user_id = self._get_user_id(user)

        tuples_to_add = []
        tuples_to_remove = []

        # Add user to default group if not a service account
        if not user.is_service_account:
            _ensure_principal_with_user_id_in_tenant(user, bootstrapped_tenant.tenant, upsert=upsert)
            tuples_to_add, tuples_to_remove = self._default_group_tuple_edits(user, mapping)

        self._replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.EXTERNAL_USER_UPDATE,
                info={"user_id": user.user_id, "org_id": user.org_id},
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
            if user.username is None:
                logger.warning(
                    "Cannot update user without username. Will bootstrap tenant but cannot update user. "
                    f"org_id={user.org_id}"
                )
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
        # This is important because usernames are only unique by tenant
        # We don't want to match a user just by username; we could end up picking the wrong one.
        existing_principal_dict = {(p.tenant.org_id, p.username): p for p in existing_principals}

        logger.info(f"Bulk import users. found_users={len(existing_principal_dict)} total_users_in_batch={len(users)}")

        for user in users:
            if not user.is_active:
                continue
            if user.org_id is None:
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
            logger.info(
                f"Add user ids. missing_user_ids={len(principals_to_update)} "
                f"found_users={len(existing_principal_dict)} total_users_in_batch={len(users)}"
            )
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
        user_id = self._get_user_id(user)
        mapping: Optional[TenantMapping] = None
        principal_uuid = ""

        logger.info(
            f"Removing Principal and group membership from RBAC and Relations. user_id={user_id} org_id={user.org_id}"
        )

        try:
            mapping = TenantMapping.objects.filter(tenant__org_id=user.org_id).get()
            default_group_uuid = str(mapping.default_group_uuid)  # type: ignore
            default_admin_group_uuid = str(mapping.default_admin_group_uuid)  # type: ignore
            tuples_to_remove.append(Group.relationship_to_user_id_for_group(default_group_uuid, user_id))
            tuples_to_remove.append(Group.relationship_to_user_id_for_group(default_admin_group_uuid, user_id))
        except TenantMapping.DoesNotExist:
            logger.info(
                "No default membership to remove. There is no tenant mapping, so the tenant must not be bootstrapped."
                f"org_id={user.org_id} user_id={user_id}"
            )

        try:
            principal = Principal.objects.filter(username=user.username, tenant__org_id=user.org_id).get()
            principal_uuid = str(principal.uuid)

            for group in principal.group.all():  # type: ignore
                group.principals.remove(principal)
                # The user id might be None for the principal so we use user instead
                tuple = group.relationship_to_principal(user)
                if tuple is None:
                    raise ValueError(f"relationship_to_principal is None for user {user_id}")
                tuples_to_remove.append(tuple)

            principal.delete()  # type: ignore
        except Principal.DoesNotExist:
            logger.info(f"Could not find Principal to remove. org_id={user.org_id} user_id={user_id}")

        if not tuples_to_remove:
            return

        self._replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.EXTERNAL_USER_DISABLE,
                info={
                    "user_id": user_id,
                    "org_id": user.org_id,
                    "mapping_id": mapping.id if mapping else None,
                    "principal_uuid": principal_uuid,
                },
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

        platform_default_groups = self._tenant_default_groups(tenant)

        kwargs = {"tenant": tenant}
        if platform_default_groups:
            group_uuid = platform_default_groups[0].uuid
            logger.info(f"Using custom default group for tenant. org_id={tenant.org_id} group_uuid={group_uuid}")
            kwargs["default_group_uuid"] = group_uuid

        mapping = TenantMapping.objects.create(**kwargs)
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
        built_in_workspaces = Workspace.objects.built_in(tenant=tenant)
        root = next(ws for ws in built_in_workspaces if ws.type == Workspace.Types.ROOT)
        default = next(ws for ws in built_in_workspaces if ws.type == Workspace.Types.DEFAULT)

        relationships = []
        relationships.extend(self._built_in_hierarchy_tuples(default.id, root.id, tenant.org_id))
        relationships.extend(self._bootstrap_default_access(tenant, mapping, str(default.id)))

        self._replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.BOOTSTRAP_TENANT,
                info={"org_id": tenant.org_id, "forced": True},
                partition_key=PartitionKey.byEnvironment(),
                add=relationships,
            )
        )

    def _query_with_default_groups(self, query_set: QuerySet) -> QuerySet:
        return query_set.prefetch_related(
            Prefetch(
                "group_set",
                queryset=Group.objects.filter(platform_default=True).order_by(),
                to_attr="_v2_bootstrap_cached_default_groups",
            )
        )

    def _fresh_tenants_with_default_groups(self, tenants: list[Tenant]) -> list[Tenant]:
        loaded = list(self._query_with_default_groups(Tenant.objects.filter(pk__in=(tenant.pk for tenant in tenants))))

        if len(loaded) != len(tenants):
            raise AssertionError(
                f"Tenant set changed concurrently. Expected {len(tenants)} tenants but got {len(loaded)}."
            )

        return loaded

    def _tenant_default_groups(self, tenant: Tenant) -> list[Group]:
        default_groups = getattr(tenant, "_v2_bootstrap_cached_default_groups", None)

        if default_groups is None:
            default_groups = list(Group.objects.filter(tenant=tenant, platform_default=True).order_by())
            tenant._v2_bootstrap_cached_default_groups = default_groups

        return default_groups

    def _get_or_bootstrap_tenants(self, org_ids: set, ready: bool) -> list[BootstrappedTenant]:
        """Bootstrap list of tenants, used by import_bulk_users."""
        # Fetch existing tenants
        existing_tenants = {
            tenant.org_id: tenant
            for tenant in Tenant.objects.filter(org_id__in=org_ids).select_related("tenant_mapping")
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
        # Set up workspace hierarchy for Tenant.
        tenants = self._fresh_tenants_with_default_groups(tenants)
        workspaces: list[Workspace] = []
        relationships: list[Relationship] = []
        mappings_to_create: list[TenantMapping] = []
        default_workspace_ids: list[UUID] = []
        for tenant in tenants:
            platform_default_groups = self._tenant_default_groups(tenant)
            kwargs = {"tenant": tenant}
            if platform_default_groups:
                group_uuid = platform_default_groups[0].uuid
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
        user_id = self._get_user_id(user)

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

    def _bootstrap_default_access(
        self, tenant: Tenant, mapping: TenantMapping, default_workspace_id: str
    ) -> List[Relationship]:
        """
        Bootstrap default access for a tenant's users and admins.

        Creates role bindings between the tenant's default workspace, default groups, and system policies.
        """
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
        if not self._tenant_default_groups(tenant):
            try:
                tuples_to_add.extend(
                    default_role_binding_tuples(
                        tenant_mapping=mapping,
                        target_workspace_uuid=default_workspace_id,
                        access_type=DefaultAccessType.USER,
                        policy_service=self._policy_service,
                    )
                )
            except DefaultGroupNotAvailableError:
                logger.warning("No platform default role found for public tenant. Default access will not be set up.")
        else:
            logger.info(
                f"Not setting up default access for tenant with customized default group. org_id={tenant.org_id}"
            )

        # Admin role binding is not customizable
        try:
            tuples_to_add.extend(
                default_role_binding_tuples(
                    tenant_mapping=mapping,
                    target_workspace_uuid=default_workspace_id,
                    access_type=DefaultAccessType.ADMIN,
                    policy_service=self._policy_service,
                )
            )
        except DefaultGroupNotAvailableError:
            logger.warning("No admin default role found for public tenant. Default access will not be set up.")

        return tuples_to_add

    def _built_in_workspaces(self, tenant: Tenant) -> tuple[Workspace, Workspace, list[Relationship]]:
        relationships = []

        root = Workspace(tenant=tenant, type=Workspace.Types.ROOT, name=Workspace.SpecialNames.ROOT)
        default = Workspace(
            parent_id=root.id,
            tenant=tenant,
            type=Workspace.Types.DEFAULT,
            name=Workspace.SpecialNames.DEFAULT,
        )

        root_workspace_id = root.id
        default_workspace_id = default.id

        relationships.extend(self._built_in_hierarchy_tuples(default_workspace_id, root_workspace_id, tenant.org_id))

        return root, default, relationships

    def create_workspace_relationships(self, pairs):
        """
        Util for bulk creating workspace relationships based on pairs.

        Input: pairs - List of tuples of (resource_id, subject_id)
        """
        relationships = []
        for pair in pairs:
            relationship = create_relationship(
                ("rbac", "workspace"),
                str(pair[0]),
                ("rbac", "workspace"),
                str(pair[1]),
                "parent",
            )
            relationships.append(relationship)
        self._replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.WORKSPACE_IMPORT,
                info={},
                partition_key=PartitionKey.byEnvironment(),
                add=relationships,
            )
        )
