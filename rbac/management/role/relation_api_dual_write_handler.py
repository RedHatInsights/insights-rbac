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

"""Class to handle Dual Write API related operations."""
import logging
from abc import ABC
from typing import Optional

from django.conf import settings
from kessel.relations.v1beta1 import common_pb2
from management.group.model import Group
from management.models import Workspace
from management.relation_replicator.noop_replicator import NoopReplicator
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import DualWriteException, PartitionKey
from management.relation_replicator.relation_replicator import RelationReplicator
from management.relation_replicator.relation_replicator import ReplicationEvent
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.role.model import BindingMapping, Role
from migration_tool.migrate_role import migrate_role
from migration_tool.sharedSystemRolesReplicatedRoleBindings import v1_perm_to_v2_perm
from migration_tool.utils import create_relationship


from api.models import Tenant


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class BaseRelationApiDualWriteHandler(ABC):
    """Base class to handle Dual Write API related operations on roles."""

    _replicator: RelationReplicator
    # TODO: continue factoring common behavior into this base class, and potentially into a higher base class
    # for the general pattern

    _expected_empty_relation_reason = None

    def __init__(self, replicator: Optional[RelationReplicator] = None):
        """Initialize SeedingRelationApiDualWriteHandler."""
        if not self.replication_enabled():
            self._replicator = NoopReplicator()
            return
        self._replicator = replicator if replicator else OutboxReplicator()

    def replication_enabled(self):
        """Check whether replication enabled."""
        return settings.REPLICATION_TO_RELATION_ENABLED is True

    def set_expected_empty_relation_reason_to_replicator(self, reason: str):
        """Set expected empty relation reason to replicator."""
        self._expected_empty_relation_reason = reason


class SeedingRelationApiDualWriteHandler(BaseRelationApiDualWriteHandler):
    """Class to handle Dual Write API related operations specific to the seeding process."""

    _replicator: RelationReplicator
    _current_role_relations: list[common_pb2.Relationship]

    _public_tenant: Optional[Tenant] = None
    _platform_default_policy_uuid: Optional[str] = None
    _admin_default_policy_uuid: Optional[str] = None

    def prepare_for_update(self, role: Role):
        """Generate & store role's current relations."""
        if not self.replication_enabled():
            return
        self._current_role_relations = self._generate_relations_for_role(role)

    def replicate_update_system_role(self, role: Role):
        """Replicate update of system role."""
        if not self.replication_enabled():
            return

        self._replicate(
            ReplicationEventType.UPDATE_SYSTEM_ROLE,
            self._create_metadata_from_role(role),
            self._current_role_relations,
            self._generate_relations_for_role(role),
        )

    def replicate_new_system_role(self, role: Role):
        """Replicate creation of new system role."""
        if not self.replication_enabled():
            return

        self._replicate(
            ReplicationEventType.CREATE_SYSTEM_ROLE,
            self._create_metadata_from_role(role),
            [],
            self._generate_relations_for_role(role),
        )

    def replicate_deleted_system_role(self, role: Role):
        """Replicate deletion of system role."""
        if not self.replication_enabled():
            return

        self._replicate(
            ReplicationEventType.DELETE_SYSTEM_ROLE,
            self._create_metadata_from_role(role),
            self._generate_relations_for_role(role),
            [],
        )

    def _generate_relations_for_role(self, role: Role) -> list[common_pb2.Relationship]:
        """Generate system role permissions."""
        relations = []

        admin_default = self._get_admin_default_policy_uuid()
        platform_default = self._get_platform_default_policy_uuid()

        # Is it valid to skip this? If there are no default groups, the migration isn't going to succeed.
        if role.admin_default and admin_default:
            relations.append(
                create_relationship(("rbac", "role"), admin_default, ("rbac", "role"), str(role.uuid), "child")
            )
        if role.platform_default and platform_default:
            relations.append(
                create_relationship(("rbac", "role"), platform_default, ("rbac", "role"), str(role.uuid), "child")
            )

        permissions = list()
        for access in role.access.all():
            v1_perm = access.permission
            v2_perm = v1_perm_to_v2_perm(v1_perm)
            permissions.append(v2_perm)

        for permission in permissions:
            relations.append(
                create_relationship(("rbac", "role"), str(role.uuid), ("rbac", "principal"), str("*"), permission)
            )

        return relations

    def _create_metadata_from_role(self, role: Role) -> dict[str, object]:
        return {"role_uuid": role.uuid}

    def _replicate(
        self,
        event_type: ReplicationEventType,
        metadata: dict[str, object],
        remove: list[common_pb2.Relationship],
        add: list[common_pb2.Relationship],
    ):
        if not self.replication_enabled():
            return
        try:
            self._replicator.replicate(
                ReplicationEvent(
                    event_type=event_type,
                    info=metadata,
                    partition_key=PartitionKey.byEnvironment(),
                    remove=remove,
                    add=add,
                ),
            )
        except Exception as e:
            raise DualWriteException(e)

    def _get_platform_default_policy_uuid(self) -> Optional[str]:
        try:
            if self._platform_default_policy_uuid is None:
                policy = Group.objects.public_tenant_only().get(platform_default=True).policies.get()
                self._platform_default_policy_uuid = str(policy.uuid)
            return self._platform_default_policy_uuid
        except Group.DoesNotExist:
            return None

    def _get_admin_default_policy_uuid(self) -> Optional[str]:
        try:
            if self._admin_default_policy_uuid is None:
                policy = Group.objects.public_tenant_only().get(admin_default=True).policies.get()
                self._admin_default_policy_uuid = str(policy.uuid)
            return self._admin_default_policy_uuid
        except Group.DoesNotExist:
            return None


class RelationApiDualWriteHandler(BaseRelationApiDualWriteHandler):
    """Class to handle Dual Write API related operations."""

    @classmethod
    def for_system_role_event(
        cls,
        role: Role,
        # TODO: may want to include Policy instead?
        tenant: Tenant,
        event_type: ReplicationEventType,
        replicator: Optional[RelationReplicator] = None,
    ):
        """Create a RelationApiDualWriteHandler for assigning / unassigning a system role for a group."""
        return cls(role, event_type, replicator, tenant)

    def __init__(
        self,
        role: Role,
        event_type: ReplicationEventType,
        replicator: Optional[RelationReplicator] = None,
        tenant: Optional[Tenant] = None,
    ):
        """Initialize RelationApiDualWriteHandler."""
        super().__init__(replicator)

        if not self.replication_enabled():
            return
        try:
            self.event_type = event_type
            self.role_relations: list[common_pb2.Relationship] = []
            self.current_role_relations: list[common_pb2.Relationship] = []
            self.role = role
            self.binding_mappings: dict[str, BindingMapping] = {}

            binding_tenant = tenant if tenant is not None else role.tenant

            if binding_tenant.tenant_name == "public":
                raise DualWriteException(
                    "Cannot bind role to public tenant. "
                    "Expected the role to have non-public tenant, or for a non-public tenant to be provided. "
                    f"Role: {role.uuid} "
                    f"Tenant: {binding_tenant.id}"
                )

            self.tenant_id = binding_tenant.id
            self.default_workspace = Workspace.objects.default(tenant=binding_tenant)
        except Exception as e:
            logger.error(f"Failed to initialize RelationApiDualWriteHandler with error: {e}")
            raise DualWriteException(e)

    def prepare_for_update(self):
        """Generate relations from current state of role and UUIDs for v2 role and role binding from database."""
        if not self.replication_enabled():
            return
        try:
            logger.info(
                "[Dual Write] Generate relations from current state of role(%s): '%s'", self.role.uuid, self.role.name
            )

            self.binding_mappings = {m.id: m for m in self.role.binding_mappings.select_for_update().all()}

            if not self.binding_mappings:
                logger.warning(
                    "[Dual Write] Binding mappings not found for role(%s): '%s'. "
                    "Assuming no current relations exist. "
                    "If this is NOT the case, relations are inconsistent!",
                    self.role.uuid,
                    self.role.name,
                )
                return

            relations, _ = migrate_role(
                self.role,
                default_workspace=self.default_workspace,
                current_bindings=self.binding_mappings.values(),
            )

            self.current_role_relations = relations
        except Exception as e:
            logger.error(f"Failed to generated relations for v2 role & role bindings: {e}")
            raise DualWriteException(e)

    def replicate_new_or_updated_role(self, role):
        """Generate replication event to outbox table."""
        if not self.replication_enabled():
            return
        self.role = role
        self._generate_relations_and_mappings_for_role()
        self._replicate()

    def replicate_deleted_role(self):
        """Replicate removal of current role state."""
        if not self.replication_enabled():
            return

        self._replicate()

    def _replicate(self):
        if not self.replication_enabled():
            return

        if self._expected_empty_relation_reason:
            logger.info(f"[Dual Write] Skipping empty replication event. {self._expected_empty_relation_reason}")
            return

        try:
            self._replicator.replicate(
                ReplicationEvent(
                    event_type=self.event_type,
                    info={
                        "binding_mappings": (self.binding_mappings if self.binding_mappings is not None else None),
                        "v1_role_uuid": str(self.role.uuid),
                        "org_id": str(self.role.tenant.org_id),
                    },
                    partition_key=PartitionKey.byEnvironment(),
                    remove=self.current_role_relations,
                    add=self.role_relations,
                ),
            )
        except Exception as e:
            logger.error(f"Failed to replicate event for role {self.role.name}, UUID :{self.role.uuid}: {e}")
            raise DualWriteException(e)

    def _generate_relations_and_mappings_for_role(self):
        """Generate relations and mappings for a role with new UUIDs for v2 role and role bindings."""
        if not self.replication_enabled():
            return []
        try:
            logger.info("[Dual Write] Generate new relations from role(%s): '%s'", self.role.uuid, self.role.name)

            relations, mappings = migrate_role(
                self.role,
                default_workspace=self.default_workspace,
                current_bindings=self.binding_mappings.values(),
            )

            prior_mappings = self.binding_mappings

            self.role_relations = relations
            self.binding_mappings = {m.id: m for m in mappings}

            # Create or update mappings as needed
            for mapping in mappings:
                if mapping.id is not None:
                    prior_mappings.pop(mapping.id)
                mapping.save()

            # Delete any mappings to resources this role no longer gives access to
            for mapping in prior_mappings.values():
                mapping.delete()

            return relations
        except Exception as e:
            logger.error(
                f"Failed to generate relations and mappings for role {self.role.name}, UUID :{self.role.uuid}: {e}"
            )
            raise DualWriteException(e)
