#
# Copyright 2024 Red Hat, Inc.
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
"""Additional tenant-related models."""

import logging
import uuid
from typing import List, Optional, Protocol
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
from api.serializers import create_tenant_name


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


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
    mapping: Optional[TenantMapping]


def get_tenant_bootstrap_service(replicator: RelationReplicator) -> "TenantBootstrapService":
    """Get a UserBootstrapService instance based on settings."""
    return V2TenantBootstrapService(replicator) if settings.V2_BOOTSTRAP_TENANT else V1TenantBootstrapService()


class TenantBootstrapService(Protocol):
    """Service for bootstrapping users in tenants."""

    def update_user(
        self, user: User, upsert: bool = False, bootstrapped_tenant: Optional[BootstrappedTenant] = None
    ) -> Optional[BootstrappedTenant]:
        """Bootstrap a user in a tenant."""
        ...

    def new_bootstrapped_tenant(self, org_id: str, account_number: Optional[str] = None) -> BootstrappedTenant:
        """Create a new tenant."""
        ...


class V1TenantBootstrapService:
    """Service for bootstrapping tenants which retains V1-only behavior."""

    _add_user_id: bool

    def __init__(self):
        """Initialize the V1TenantBootstrapService."""
        self._add_user_id = settings.V1_BOOTSTRAP_ADD_USER_ID

    def new_bootstrapped_tenant(self, org_id: str, account_number: Optional[str] = None) -> BootstrappedTenant:
        """Create a new tenant."""
        return self._get_or_bootstrap_tenant(org_id, account_number)

    def update_user(
        self, user: User, upsert: bool = False, bootstrapped_tenant: Optional[BootstrappedTenant] = None
    ) -> Optional[BootstrappedTenant]:
        """Bootstrap a user in a tenant."""
        if user.is_active:
            return self._update_active_user(user, upsert)
        else:
            return self._update_inactive_user(user)

    def _update_active_user(self, user: User, upsert: bool) -> Optional[BootstrappedTenant]:
        bootstrapped = self._get_or_bootstrap_tenant(user.org_id, user.account)

        if self._add_user_id:
            _ensure_principal_with_user_id_in_tenant(user, bootstrapped.tenant, upsert=upsert)

        return bootstrapped

    def _get_or_bootstrap_tenant(self, org_id: str, account_number: Optional[str] = None) -> BootstrappedTenant:
        tenant_name = create_tenant_name(account_number)
        tenant, _ = Tenant.objects.get_or_create(
            org_id=org_id,
            defaults={"ready": True, "account_id": account_number, "tenant_name": tenant_name},
        )
        return BootstrappedTenant(tenant=tenant, mapping=None)

    def _update_inactive_user(self, user: User) -> None:
        try:
            tenant = Tenant.objects.get(org_id=user.org_id)
            principal = Principal.objects.get(username=user.username, tenant=tenant)
            groups = []
            for group in principal.group.all():
                groups.append(group)
                # We have to do the removal explicitly in order to clear the cache,
                # or the console will still show the cached number of members
                group.principals.remove(principal)
            principal.delete()
            if not groups:
                logger.info(f"Principal {user.user_id} was not under any groups.")
            for group in groups:
                logger.info(f"Principal {user.user_id} was in group with uuid: {group.uuid}")
        except (Tenant.DoesNotExist, Principal.DoesNotExist):
            return None


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
        if not user.is_active:
            self._disable_user_in_tenant(user)
            return

        bootstrapped_tenant = bootstrapped_tenant or self._get_or_bootstrap_tenant(user.org_id, user.account)
        mapping = bootstrapped_tenant.mapping
        if mapping is None:
            raise ValueError("Expected TenantMapping but got None.")

        user_id = user.user_id

        if user_id is None:
            raise ValueError(f"User {user.username} has no user_id.")

        tuples_to_add = []
        tuples_to_remove = []

        # Add user to default group if not a service account
        if not user.is_service_account:
            _ensure_principal_with_user_id_in_tenant(user, bootstrapped_tenant.tenant, upsert=upsert)

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

        self._replicator.replicate(
            ReplicationEvent(
                type=ReplicationEventType.EXTERNAL_USER_UPDATE,
                info={"user_id": user_id},
                partition_key="rbactodo",
                add=tuples_to_add,
                remove=tuples_to_remove,
            )
        )

        return bootstrapped_tenant

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
                group: Group
                group.principals.remove(principal)
                tuples_to_remove.append(group.relationship_to_principal(principal))

            principal.delete()
        except Principal.DoesNotExist:
            pass

        self._replicator.replicate(
            ReplicationEvent(
                type=ReplicationEventType.EXTERNAL_USER_UPDATE,
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

        self._replicator.replicate(
            ReplicationEvent(
                type=ReplicationEventType.BOOTSTRAP_TENANT,
                info={"org_id": tenant.org_id, "default_workspace_uuid": str(default_workspace.uuid)},
                partition_key="rbactodo",
                add=relationships,
            )
        )

        return BootstrappedTenant(tenant, mapping)

    def _bootstrap_default_access(
        self, tenant: Tenant, mapping: TenantMapping, default_workspace: Workspace
    ) -> List[Relationship]:
        """
        Bootstrap default access for a tenant's users and admins.

        Creates role bindings between the tenant's default workspace, default groups, and system policies.
        """
        platform_default_role = self._get_platform_default_policy_uuid()
        admin_default_role = self._get_admin_default_policy_uuid()

        if platform_default_role is None:
            logger.warning("No platform default role found for public tenant. Default access will not be set up.")

        if admin_default_role is None:
            logger.warning("No admin default role found for public tenant. Default access will not be set up.")

        default_workspace_uuid = str(default_workspace.uuid)
        default_user_role_binding_uuid = str(mapping.default_user_role_binding_uuid)
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
        if platform_default_role and not Group.objects.filter(platform_default=True, tenant=tenant).exists():
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
                        "subject",
                        "member",
                    ),
                ]
            )

        # Admin role binding is not customizable
        if admin_default_role:
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
                        "subject",
                        "member",
                    ),
                ]
            )

        return tuples_to_add

    def _get_platform_default_policy_uuid(self) -> Optional[str]:
        try:
            if self._platform_default_policy_uuid is None:
                # TODO this doesnt always exist in tests
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


def _ensure_principal_with_user_id_in_tenant(user: User, tenant: Tenant, upsert: bool = False):
    created = False
    principal = None

    if upsert:
        principal, created = Principal.objects.get_or_create(
            username=user.username,
            tenant=tenant,
            defaults={"user_id": user.user_id},
        )
    else:
        try:
            principal = Principal.objects.get(username=user.username, tenant=tenant)
        except Principal.DoesNotExist:
            pass

    if not created and principal and principal.user_id != user.user_id:
        principal.user_id = user.user_id
        principal.save()
