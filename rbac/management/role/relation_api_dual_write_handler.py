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
from management.group.platform import DefaultGroupNotAvailableError, GlobalPolicyIdService
from management.models import Workspace
from management.permission.scope_service import ImplicitResourceService, Scope, bound_model_for_scope
from management.relation_replicator.noop_replicator import NoopReplicator
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import DualWriteException, PartitionKey
from management.relation_replicator.relation_replicator import RelationReplicator
from management.relation_replicator.relation_replicator import ReplicationEvent
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.role.model import BindingMapping, Role
from management.role.platform import platform_v2_role_uuid_for
from management.role.relations import role_child_relationship
from management.tenant_mapping.model import DefaultAccessType
from migration_tool.migrate_role import migrate_role, relation_tuples_for_bindings
from migration_tool.models import V2boundresource
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

    def __init__(self, role: Role, replicator: Optional[RelationReplicator] = None):
        """Initialize SeedingRelationApiDualWriteHandler."""
        super().__init__(replicator)
        self.implicit_resource_service = ImplicitResourceService.from_settings()
        self.role = role

    def prepare_for_update(self):
        """Generate & store role's current relations."""
        if not self.replication_enabled():
            return
        self._current_role_relations = self._generate_relations_for_role(list_all_possible_scopes_for_removal=True)

    def replicate_update_system_role(self):
        """Replicate update of system role."""
        if not self.replication_enabled():
            return

        self._replicate(
            ReplicationEventType.UPDATE_SYSTEM_ROLE,
            self._create_metadata_from_role(),
            self._current_role_relations,
            self._generate_relations_for_role(),
        )

    def replicate_new_system_role(self):
        """Replicate creation of new system role."""
        if not self.replication_enabled():
            return

        self._replicate(
            ReplicationEventType.CREATE_SYSTEM_ROLE,
            self._create_metadata_from_role(),
            [],
            self._generate_relations_for_role(),
        )

    def replicate_deleted_system_role(self):
        """Replicate deletion of system role."""
        if not self.replication_enabled():
            return

        self._replicate(
            ReplicationEventType.DELETE_SYSTEM_ROLE,
            self._create_metadata_from_role(),
            self._generate_relations_for_role(list_all_possible_scopes_for_removal=True),
            [],
        )

    def _check_create_admin_platform_relation(self, role, role_scope):
        create_relations = []
        """Check system role and create admin and platform system role parent-child relationship."""
        if role.admin_default:
            try:
                parent_uuid = platform_v2_role_uuid_for(
                    DefaultAccessType.ADMIN,
                    role_scope,
                    GlobalPolicyIdService.shared(),
                )

                create_parent_child_relationship = role_child_relationship(parent_uuid, self.role.uuid)
                create_relations.append(create_parent_child_relationship)
            except DefaultGroupNotAvailableError:
                # Default groups may not exist yet during seeding, skip parent relationship
                logging.warning(f"Default groups may not exist yet during seeding for admin scope {role_scope}")
                pass

        if role.platform_default:
            try:
                parent_uuid = platform_v2_role_uuid_for(
                    DefaultAccessType.USER,
                    role_scope,
                    GlobalPolicyIdService.shared(),
                )

                create_parent_child_relationship = role_child_relationship(parent_uuid, self.role.uuid)
                create_relations.append(create_parent_child_relationship)
            except DefaultGroupNotAvailableError:
                # Default groups may not exist yet during seeding, skip parent relationship
                logging.warning(f"Default groups may not exist yet during seeding for platform scope {role_scope}")
                pass

        return create_relations

    def _generate_relations_for_role(
        self, list_all_possible_scopes_for_removal=False
    ) -> list[common_pb2.Relationship]:
        """Generate system role permissions."""
        relations = []
        # Gather v1 and v2 permissions for the role
        v2_permissions: list[str] = []

        for access in self.role.access.all():
            v1_perm = access.permission
            v2_perm = v1_perm_to_v2_perm(v1_perm)
            v2_permissions.append(v2_perm)

            # When deleting, generate relationships for all possible scopes
        if list_all_possible_scopes_for_removal is True:
            for scope in Scope:
                relations.extend(self._check_create_admin_platform_relation(self.role, scope))
        else:
            # Determine highest scope for the role's permissions
            highest_scope: Scope = self.implicit_resource_service.scope_for_role(self.role)
            relations.extend(self._check_create_admin_platform_relation(self.role, highest_scope))

        for permission in v2_permissions:
            relations.append(
                create_relationship(
                    ("rbac", "role"),
                    str(self.role.uuid),
                    ("rbac", "principal"),
                    str("*"),
                    permission,
                )
            )
        return relations

    def _create_metadata_from_role(self) -> dict[str, object]:
        return {"role_uuid": self.role.uuid}

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


class RelationApiDualWriteHandler(BaseRelationApiDualWriteHandler):
    """Class to handle Dual Write API related operations."""

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

            self.tenant = binding_tenant
            self.root_workspace = Workspace.objects.root(tenant=binding_tenant)
            self.default_workspace = Workspace.objects.default(tenant=binding_tenant)

            self.resource_service = ImplicitResourceService.from_settings()
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

            self.current_role_relations = relation_tuples_for_bindings(self.binding_mappings.values())
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

            target_model = bound_model_for_scope(
                scope=self.resource_service.scope_for_role(self.role),
                tenant=self.tenant,
                root_workspace=self.root_workspace,
                default_workspace=self.default_workspace,
            )

            target_resource = V2boundresource.for_model(target_model)

            relations, mappings = migrate_role(
                self.role,
                default_resource=target_resource,
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
