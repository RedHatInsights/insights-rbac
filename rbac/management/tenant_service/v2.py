"""V2 implementation of Tenant bootstrapping."""

from typing import List, Optional

from django.conf import settings
from django.db import models, transaction
from kessel.relations.v1beta1.common_pb2 import Relationship
from management.group.model import Group
from management.principal.model import Principal
from management.relation_replicator.relation_replicator import ReplicationEvent, ReplicationEventType
from management.relation_replicator.relation_replicator import RelationReplicator
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

    @transaction.atomic
    def new_bootstrapped_tenant(self, org_id: str, account_number: Optional[str] = None) -> BootstrappedTenant:
        """Create a new tenant."""
        tenant = Tenant.objects.create(org_id=org_id, account_id=account_number)
        return self._bootstrap_tenant(tenant)

    @transaction.atomic
    def bootstrap_tenant(self, tenant: Tenant) -> BootstrappedTenant:
        """Bootstrap an existing tenant."""
        try:
            mapping = TenantMapping.objects.get(tenant=tenant)
            return BootstrappedTenant(tenant=tenant, mapping=mapping)
        except TenantMapping.DoesNotExist:
            return self._bootstrap_tenant(tenant)

    @transaction.atomic
    def update_user(
        self, user: User, upsert: bool = False, bootstrapped_tenant: Optional[BootstrappedTenant] = None
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

        bootstrapped_tenant = bootstrapped_tenant or self._get_or_bootstrap_tenant(user.org_id, user.account)
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
                partition_key="rbactodo",
                add=tuples_to_add,
                remove=tuples_to_remove,
            )
        )

        return bootstrapped_tenant

    @transaction.atomic
    def update_users(self, users: list[User]):
        """
        Bootstrap multiple users in a tenant.

        Create each users' Tenant (and bootstrap it) if it does not exist.
        Updates each [Principal] with the user's user_id if Principal exists but user_id not set.

        Args:
            users (list): List of User objects to update
        """
        bootstrapped_list = []
        for user in users:
            if user.org_id is None:
                logger.warning(f"Cannot update user without org_id. Skipping. username={user.username}")
                continue
            bootstrapped_list.append(self._get_or_bootstrap_tenant(user.org_id, user.account))
        bootstrapped_mapping = {bootstrapped.tenant.org_id: bootstrapped for bootstrapped in bootstrapped_list}

        tuples_to_add = []
        tuples_to_remove = []
        principals_to_update = []

        # Fetch existing principals
        tenants = [bootstrapped.tenant for bootstrapped in bootstrapped_list]
        existing_principals = Principal.objects.filter(
            models.Q(tenant__in=tenants) & models.Q(username__in=[user.username for user in users])
        ).prefetch_related("tenant")
        # Mapping of (org_id, username) -> principal
        existing_principal_dict = {(p.tenant.org_id, p.username): p for p in existing_principals}

        for user in users:
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
                event_type=ReplicationEventType.EXTERNAL_USER_UPDATE,
                info={"bulk_import": ",".join([user.user_id for user in users if user.user_id is not None])},
                partition_key="rbactodo",
                add=tuples_to_add,
                remove=tuples_to_remove,
            )
        )

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
        try:
            mapping = TenantMapping.objects.get(tenant=tenant)
            return BootstrappedTenant(
                tenant=tenant,
                mapping=mapping,
            )
        except TenantMapping.DoesNotExist:
            bootstrap = self._bootstrap_tenant(tenant)
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
        tenant_id = f"{self._user_domain}/{tenant.org_id}"
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

        self._replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.BOOTSTRAP_TENANT,
                info={"org_id": tenant.org_id, "default_workspace_uuid": str(default_workspace.uuid)},
                partition_key="rbactodo",
                add=relationships,
            )
        )

        return BootstrappedTenant(tenant, mapping, default_workspace=default_workspace, root_workspace=root_workspace)

    def _bootstrap_default_access(
        self, tenant: Tenant, mapping: TenantMapping, default_workspace: Workspace
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

        default_workspace_uuid = str(default_workspace.uuid)
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
        if platform_default_role_uuid and not Group.objects.filter(platform_default=True, tenant=tenant).exists():
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
                        platform_default_role_uuid,
                        "role",
                    ),
                    create_relationship(
                        ("rbac", "role_binding"),
                        default_user_role_binding_uuid,
                        ("rbac", "group"),
                        str(mapping.default_group_uuid),
                        "subject",
                        "member",
                    ),
                ]
            )

        # Admin role binding is not customizable
        if admin_default_role_uuid:
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
                        admin_default_role_uuid,
                        "role",
                    ),
                    create_relationship(
                        ("rbac", "role_binding"),
                        default_admin_role_binding_uuid,
                        ("rbac", "group"),
                        str(mapping.default_admin_group_uuid),
                        "subject",
                        "member",
                    ),
                ]
            )

        return tuples_to_add

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
