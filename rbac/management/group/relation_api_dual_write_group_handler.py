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
from typing import Iterable, Optional

from kessel.relations.v1beta1.common_pb2 import Relationship
from management.group.model import Group
from management.group.relation_api_dual_write_subject_handler import RelationApiDualWriteSubjectHandler
from management.models import Workspace
from management.principal.model import Principal
from management.relation_replicator.relation_replicator import (
    DualWriteException,
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.role.model import BindingMapping, Role
from management.tenant_mapping.model import TenantMapping
from migration_tool.utils import create_relationship

from api.models import Tenant

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationApiDualWriteGroupHandler(RelationApiDualWriteSubjectHandler):
    """Class to handle Dual Write for group bindings and membership."""

    group: Group
    _expected_empty_relation_reason = None

    def __init__(
        self,
        group,
        event_type: ReplicationEventType,
        replicator: Optional[RelationReplicator] = None,
        enable_replication_for_migrator: Optional[bool] = False,
    ):
        """Initialize RelationApiDualWriteGroupHandler."""
        try:
            self.group = group
            self.principals = []
            self._platform_default_policy_uuid: Optional[str] = None
            self._public_tenant: Optional[Tenant] = None
            self._tenant_mapping = None
            self.enable_replication_for_migrator = enable_replication_for_migrator
            default_workspace = Workspace.objects.get(tenant_id=self.group.tenant_id, type=Workspace.Types.DEFAULT)
            super().__init__(
                default_workspace,
                event_type,
                replicator,
                enable_replication_for_migrator=self.enable_replication_for_migrator,
            )
        except Exception as e:
            raise DualWriteException(e)

    def _generate_member_relations(self):
        """Generate user-groups relations."""
        relations = []
        for principal in self.principals:
            relationship = self.group.relationship_to_principal(principal)
            if relationship is None:
                logger.warning(
                    "[Dual Write] Principal(uuid=%s) does not have user_id. Skipping replication.", principal.uuid
                )
                continue
            relations.append(relationship)

        return relations

    def generate_relations_to_add_principals(self, principals: list[Principal]):
        """Generate relations to add principals."""
        if not self.replication_enabled():
            return
        logger.info("[Dual Write] Generate new relations from Group(%s): '%s'", self.group.uuid, self.group.name)
        self.principals = principals
        self.relations_to_add = self._generate_member_relations()

    def replicate_new_principals(self, principals: list[Principal]):
        """Replicate new principals into group."""
        if not self.replication_enabled():
            return
        self.generate_relations_to_add_principals(principals)
        self._replicate()

    def replicate_removed_principals(self, principals: list[Principal]):
        """Replicate removed principals from group."""
        if not self.replication_enabled():
            return
        logger.info("[Dual Write] Generate new relations from Group(%s): '%s'", self.group.uuid, self.group.name)
        self.principals = principals
        self.relations_to_remove = self._generate_member_relations()

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
                    info={"group_uuid": str(self.group.uuid), "org_id": str(self.group.tenant.org_id)},
                    partition_key=PartitionKey.byEnvironment(),
                    remove=self.relations_to_remove,
                    add=self.relations_to_add,
                ),
            )
        except Exception as e:
            raise DualWriteException(e)

    def generate_relations_to_add_roles(
        self, roles: Iterable[Role], remove_default_access_from: Optional[TenantMapping] = None
    ):
        """Generate relations to add roles."""
        if not self.replication_enabled():
            return

        def add_group_to_binding(mapping: BindingMapping):
            self.relations_to_add.append(mapping.add_group_to_bindings(str(self.group.uuid)))

        for role in roles:
            self._update_mapping_for_role(
                role,
                update_mapping=add_group_to_binding,
                create_default_mapping_for_system_role=lambda: self._create_default_mapping_for_system_role(
                    role, groups=frozenset([str(self.group.uuid)])
                ),
            )

        if remove_default_access_from is not None:
            default_binding = self._default_binding(mapping=remove_default_access_from)
            self.relations_to_remove.append(default_binding)

    def replicate(self):
        """Replicate generated relations."""
        if not self.replication_enabled():
            return

        self._replicate()

    def generate_relations_to_remove_roles(self, roles: Iterable[Role]):
        """Generate relations to removed roles."""
        if not self.replication_enabled():
            return

        for role in roles:
            self._update_mapping_for_role_removal(role)

    def _update_mapping_for_role_removal(self, role: Role):
        def remove_group_from_binding(mapping: BindingMapping):
            removal = mapping.remove_group_from_bindings(str(self.group.uuid))
            if removal is not None:
                self.relations_to_remove.append(removal)

        self._update_mapping_for_role(
            role, update_mapping=remove_group_from_binding, create_default_mapping_for_system_role=None
        )

    def prepare_to_delete_group(self, roles):
        """Generate relations to delete."""
        if not self.replication_enabled():
            return

        system_roles = roles.public_tenant_only()

        # Custom roles are locked to prevent resources from being added/removed concurrently,
        # in the case that the Roles had _no_ resources specified to begin with.
        # This should not be necessary for system roles.
        custom_roles = roles.filter(tenant=self.group.tenant).select_for_update()

        custom_ids = []
        for role in [*system_roles, *custom_roles]:
            if role.id in custom_ids:
                # it was needed to skip distinct clause because distinct doesn't work with select_for_update
                continue
            self._update_mapping_for_role_removal(role)
            custom_ids.append(role.id)

        if self.group.platform_default:
            self.relations_to_add.append(self._default_binding())
        else:
            self.principals = self.group.principals.all()
            self.relations_to_remove.extend(self._generate_member_relations())

    def _default_binding(self, mapping: Optional[TenantMapping] = None) -> Relationship:
        """Calculate default bindings from tenant mapping."""
        if mapping is None:
            mapping = TenantMapping.objects.get(tenant=self.group.tenant)
        else:
            assert mapping.tenant.id == self.group.tenant_id, "Tenant mapping does not match group tenant."

        return create_relationship(
            ("rbac", "workspace"),
            str(self.default_workspace.id),
            ("rbac", "role_binding"),
            str(mapping.default_role_binding_uuid),
            "binding",
        )

    def set_expected_empty_relation_reason(self, reason):
        """Set expected empty relation reason."""
        self._expected_empty_relation_reason = reason
