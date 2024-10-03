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
from typing import Callable, Iterable, Optional
from uuid import uuid4

from django.conf import settings
from management.principal.model import Principal
from management.role.model import BindingMapping, Role
from management.role.relation_api_dual_write_handler import (
    DualWriteException,
    OutboxReplicator,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from migration_tool.models import V2boundresource, V2role, V2rolebinding
from migration_tool.utils import create_relationship

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationApiDualWriteGroupHandler:
    """Class to handle Dual Write API related operations."""

    def __init__(
        self,
        group,
        event_type: ReplicationEventType,
        principals: list[Principal],
        replicator: Optional[RelationReplicator] = None,
    ):
        """Initialize RelationApiDualWriteGroupHandler."""
        if not self.replication_enabled():
            return
        try:
            self.group_relations_to_add = []
            self.group_relations_to_remove = []
            self.principals = principals
            self.group = group
            self.event_type = event_type
            self._replicator = replicator if replicator else OutboxReplicator(group)
        except Exception as e:
            raise DualWriteException(e)

    def replication_enabled(self):
        """Check whether replication enabled."""
        return settings.REPLICATION_TO_RELATION_ENABLED is True

    def _generate_relations(self):
        """Generate user-groups relations."""
        relations = []
        for principal in self.principals:
            relations.append(
                create_relationship(
                    ("rbac", "group"), str(self.group.uuid), ("rbac", "user"), str(principal.uuid), "member"
                )
            )

        return relations

    def replicate_new_principals(self):
        """Replicate new principals into group."""
        if not self.replication_enabled():
            return
        logger.info("[Dual Write] Generate new relations from Group(%s): '%s'", self.group.uuid, self.group.name)

        self.group_relations_to_add = self._generate_relations()
        self._replicate()

    def replicate_removed_principals(self):
        """Replicate removed principals from group."""
        if not self.replication_enabled():
            return
        logger.info("[Dual Write] Generate new relations from Group(%s): '%s'", self.group.uuid, self.group.name)

        self.group_relations_to_remove = self._generate_relations()

        self._replicate()

    def _replicate(self):
        if not self.replication_enabled():
            return
        try:
            self._replicator.replicate(
                ReplicationEvent(
                    type=self.event_type,
                    # TODO: need to think about partitioning
                    # Maybe resource id
                    partition_key="rbactodo",
                    remove=self.group_relations_to_remove,
                    add=self.group_relations_to_add,
                ),
            )
        except Exception as e:
            raise DualWriteException(e)

    def replicate_added_role(self, role: Role):
        """Replicate added role."""
        if not self.replication_enabled():
            return
        # TODO - This needs to be removed to seed the default groups.
        if self.group.tenant.tenant_name == "public":
            return

        def add_group_to_binding(mapping: BindingMapping):
            self.group_relations_to_add.append(mapping.add_group_to_bindings(str(self.group.uuid)))

        def create_default_mapping():
            assert role.system is True, "Expected system role. Mappings for custom roles must already be created."
            binding = V2rolebinding(
                str(uuid4()),
                # Assumes same role UUID for V2 system role equivalent.
                V2role.for_system_role(str(role.uuid)),
                # TODO: don't use org id once we have workspace built ins
                V2boundresource(("rbac", "workspace"), self.group.tenant.org_id),
                groups=frozenset([str(self.group.uuid)]),
            )
            mapping = BindingMapping.for_role_binding(binding, role)
            self.group_relations_to_add.extend(mapping.as_tuples())
            return mapping

        self._update_mapping_for_role(
            role, update_mapping=add_group_to_binding, create_default_mapping_for_system_role=create_default_mapping
        )
        self._replicate()

    def replicate_removed_role(self, role: Role):
        """Replicate removed role."""
        if not self.replication_enabled():
            return
        # TODO - This needs to be removed to seed the default groups.
        if self.group.tenant.tenant_name == "public":
            return

        def remove_group_from_binding(mapping: BindingMapping):
            self.group_relations_to_remove.append(mapping.remove_group_from_bindings(str(self.group.uuid)))

        self._update_mapping_for_role(
            role, update_mapping=remove_group_from_binding, create_default_mapping_for_system_role=lambda: None
        )
        self._replicate()

    def _update_mapping_for_role(
        self,
        role: Role,
        update_mapping: Callable[[BindingMapping], None],
        create_default_mapping_for_system_role: Callable[[], Optional[BindingMapping]],
    ):
        """
        Update mapping for role using callbacks based on current state.

        Callbacks are expected to modify [self.group_relations_to_add] and [self.group_relations_to_remove].
        This method handles persistence and locking itself.
        """
        if not self.replication_enabled():
            return
        # TODO - This needs to be removed to seed the default groups.
        if self.group.tenant.tenant_name == "public":
            return

        if role.system:
            try:
                # We lock the binding here because we cannot lock the Role for system roles,
                # as they are used platform-wide,
                # and their permissions do not refer to specific resources,
                # so they can be changed concurrently safely.
                mapping = (
                    BindingMapping.objects.select_for_update()
                    .filter(
                        role=role,
                        resource_type_namespace="rbac",
                        resource_type_name="workspace",
                        # TODO: don't use org id once we have workspace built ins
                        resource_id=self.group.tenant.org_id,
                    )
                    .get()
                )
                update_mapping(mapping)
                mapping.save(force_update=True)

                if mapping.is_unassigned():
                    self.group_relations_to_remove.extend(mapping.as_tuples())
                    mapping.delete()
            except BindingMapping.DoesNotExist:
                mapping = create_default_mapping_for_system_role()
                if mapping is not None:
                    mapping.save(force_insert=True)
        else:
            # NOTE: The custom Role MUST be locked before this point in Read Committed isolation.
            # There is a risk of write skew here otherwise, in the case that permissions are added
            # to a custom role that currently has no permissions.
            # In that case there would be no bindings to lock.
            # We must lock something to prevent concurrent updates, so we lock the Role.
            # Because custom roles must be locked already by this point,
            # we don't need to lock the binding here.
            bindings: Iterable[BindingMapping] = role.binding_mappings.all()

            if not bindings:
                logger.warning(
                    "[Dual Write] Binding mappings not found for role(%s): '%s'. "
                    "Assuming no current relations exist. "
                    "If this is NOT the case, relations are inconsistent!",
                    role.uuid,
                    role.name,
                )

            for mapping in bindings:
                update_mapping(mapping)
                mapping.save(force_update=True)
