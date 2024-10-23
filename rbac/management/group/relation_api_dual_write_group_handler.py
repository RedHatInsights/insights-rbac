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
from management.group.model import Group
from management.models import Workspace
from management.principal.model import Principal
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    DualWriteException,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.role.model import BindingMapping, Role
from migration_tool.models import V2boundresource, V2role, V2rolebinding


from api.models import Tenant

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationApiDualWriteGroupHandler:
    """Class to handle Dual Write API related operations."""

    group: Group

    def __init__(
        self,
        group,
        event_type: ReplicationEventType,
        replicator: Optional[RelationReplicator] = None,
    ):
        """Initialize RelationApiDualWriteGroupHandler."""
        if not self.replication_enabled():
            return
        try:
            self.group_relations_to_add = []
            self.group_relations_to_remove = []
            self.principals = []
            self.group = group
            self.default_workspace = Workspace.objects.get(
                tenant_id=self.group.tenant_id, type=Workspace.Types.DEFAULT
            )
            self.event_type = event_type
            self.user_domain = settings.PRINCIPAL_USER_DOMAIN
            self._replicator = replicator if replicator else OutboxReplicator()
        except Exception as e:
            raise DualWriteException(e)

    def replication_enabled(self):
        """Check whether replication enabled."""
        return settings.REPLICATION_TO_RELATION_ENABLED is True

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

    def replicate_new_principals(self, principals: list[Principal]):
        """Replicate new principals into group."""
        if not self.replication_enabled():
            return
        logger.info("[Dual Write] Generate new relations from Group(%s): '%s'", self.group.uuid, self.group.name)
        self.principals = principals
        self.group_relations_to_add = self._generate_member_relations()
        self._replicate()

    def replicate_removed_principals(self, principals: list[Principal]):
        """Replicate removed principals from group."""
        if not self.replication_enabled():
            return
        logger.info("[Dual Write] Generate new relations from Group(%s): '%s'", self.group.uuid, self.group.name)
        self.principals = principals
        self.group_relations_to_remove = self._generate_member_relations()

        self._replicate()

    def _replicate(self):
        if not self.replication_enabled():
            return
        try:
            self._replicator.replicate(
                ReplicationEvent(
                    event_type=self.event_type,
                    info={"group_uuid": str(self.group.uuid)},
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

        def add_group_to_binding(mapping: BindingMapping):
            self.group_relations_to_add.append(mapping.add_group_to_bindings(str(self.group.uuid)))

        def create_default_mapping():
            assert role.system is True, "Expected system role. Mappings for custom roles must already be created."
            binding = V2rolebinding(
                str(uuid4()),
                # Assumes same role UUID for V2 system role equivalent.
                V2role.for_system_role(str(role.uuid)),
                V2boundresource(("rbac", "workspace"), str(self.default_workspace.uuid)),
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

        self._update_mapping_for_role_removal(role)
        self._replicate()

    def _update_mapping_for_role_removal(self, role: Role):
        def remove_group_from_binding(mapping: BindingMapping):
            self.group_relations_to_remove.append(mapping.remove_group_from_bindings(str(self.group.uuid)))

        self._update_mapping_for_role(
            role, update_mapping=remove_group_from_binding, create_default_mapping_for_system_role=lambda: None
        )

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
                        resource_id=str(self.default_workspace.uuid),
                    )
                    .get()
                )

                update_mapping(mapping)

                if mapping.is_unassigned():
                    self.group_relations_to_remove.extend(mapping.as_tuples())
                    mapping.delete()
                else:
                    mapping.save(force_update=True)
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

    def prepare_to_delete_group(self):
        """Generate relations to delete."""
        if not self.replication_enabled():
            return
        roles = Role.objects.filter(policies__group=self.group)

        system_roles = roles.filter(tenant=Tenant.objects.get(tenant_name="public"))

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
            pass  # TODO: create default bindings,
        else:
            self.principals = self.group.principals.all()
            self.group_relations_to_remove.extend(self._generate_member_relations())

    def replicate_deleted_group(self):
        """Prepare for delete."""
        if not self.replication_enabled():
            return
        self._replicate()
