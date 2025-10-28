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
from management.models import Workspace
from management.permission.scope_service import Scope, bound_model_for_scope
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    DualWriteException,
    RelationReplicator,
    ReplicationEventType,
)
from management.role.model import BindingMapping, Role
from migration_tool.models import V2boundresource, V2role, V2rolebinding

from api.models import Tenant

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationApiDualWriteSubjectHandler:
    """Base class to handle dual write algorithm for bindings to subjects."""

    def __init__(
        self,
        tenant: Tenant,
        root_workspace: Workspace,
        default_workspace: Workspace,
        event_type: ReplicationEventType,
        replicator: Optional[RelationReplicator] = None,
    ):
        """Initialize RelationApiDualWriteSubjectHandler."""
        if not self.replication_enabled():
            return

        try:
            self.relations_to_add = []
            self.relations_to_remove = []

            self.tenant = tenant
            self.root_workspace = root_workspace
            self.default_workspace = default_workspace

            if self.root_workspace.tenant != self.tenant:
                raise ValueError(
                    f"Expected root workspace to be from tenant {self.tenant}, but got {self.root_workspace.tenant}"
                )

            if self.default_workspace.tenant != self.tenant:
                raise ValueError(
                    f"Expected root workspace to be from tenant {self.tenant}, but got {self.default_workspace.tenant}"
                )

            self.event_type = event_type
            self._replicator = replicator if replicator else OutboxReplicator()
        except Exception as e:
            logger.error(f"Initialization of RelationApiDualWriteSubjectHandler failed: {e}")
            raise DualWriteException(e)

    def replication_enabled(self):
        """Check whether replication enabled."""
        return settings.REPLICATION_TO_RELATION_ENABLED is True

    def _create_default_mapping_for_system_role(
        self,
        system_role: Role,
        resource: V2boundresource,
        **subject: Iterable[str],
    ) -> BindingMapping:
        """Create default mapping."""
        assert system_role.system is True, "Expected system role. Mappings for custom roles must already be created."
        binding = V2rolebinding(
            str(uuid4()),
            # Assumes same role UUID for V2 system role equivalent.
            V2role.for_system_role(str(system_role.uuid)),
            resource,
            **subject,
        )
        mapping = BindingMapping.for_role_binding(binding, system_role)
        self.relations_to_add.extend(mapping.as_tuples())
        return mapping

    def _update_mapping_for_role(
        self,
        role: Role,
        scope: Scope,
        update_mapping: Callable[[BindingMapping], None],
        create_default_mapping_for_system_role: Optional[Callable[[V2boundresource], BindingMapping]],
    ):
        """
        Update mapping for role using callbacks based on current state.

        Callbacks are expected to modify [self.relations_to_add] and [self.relations_to_remove].
        This method handles persistence and locking itself.
        """
        if not self.replication_enabled():
            return

        if role.system:
            self._update_mapping_for_system_role(
                role,
                scope=scope,
                update_mapping=update_mapping,
                create_default_mapping_for_system_role=create_default_mapping_for_system_role,
                resource_locked=False,
            )
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

    def _lock_resource_for_update(self, resource: Tenant | Workspace):
        if isinstance(resource, Tenant):
            Tenant.objects.select_for_update().get(pk=resource.pk)
        elif isinstance(resource, Workspace):
            Workspace.objects.select_for_update().get(pk=resource.pk)
        else:
            raise TypeError(f"Unexpected resource: {resource}")

    def _update_mapping_for_system_role(
        self,
        role: Role,
        scope: Scope,
        update_mapping: Callable[[BindingMapping], None],
        create_default_mapping_for_system_role: Optional[Callable[[V2boundresource], BindingMapping]],
        resource_locked: bool = False,
    ):
        if role.system is False:
            raise DualWriteException("Expected system role.")

        local_resource = bound_model_for_scope(
            scope=scope,
            tenant=self.tenant,
            root_workspace=self.root_workspace,
            default_workspace=self.default_workspace,
        )

        v2_resource = V2boundresource.for_model(local_resource)

        try:
            # We lock the binding here because we cannot lock the Role for system roles,
            # as they are used platform-wide,
            # and their permissions do not refer to specific resources,
            # so they can be changed concurrently safely.
            mapping = (
                BindingMapping.objects.select_for_update()
                .filter(
                    role=role,
                    resource_type_namespace=v2_resource.resource_type[0],
                    resource_type_name=v2_resource.resource_type[1],
                    resource_id=v2_resource.resource_id,
                )
                .get()
            )

            update_mapping(mapping)

            if mapping.is_unassigned():
                self.relations_to_remove.extend(mapping.as_tuples())
                mapping.delete()
            else:
                mapping.save(force_update=True)
        except BindingMapping.DoesNotExist:
            # create_default_mapping_for_system_role is None if e.g. the role is being removed.
            if create_default_mapping_for_system_role is not None:
                if not resource_locked:
                    # Lock the resource to prevent concurrent creation of the same mapping.
                    self._lock_resource_for_update(local_resource)
                    # Recurse in case the workspace was locked by another process
                    # and now the mapping exists.
                    # We need to query and also lock the existing mapping in that case,
                    # just like normal.
                    self._update_mapping_for_system_role(
                        role,
                        scope=scope,
                        update_mapping=update_mapping,
                        create_default_mapping_for_system_role=create_default_mapping_for_system_role,
                        # This prevents infinite recursion.
                        resource_locked=True,
                    )
                else:
                    # The resource is locked, so it's safe to create the mapping.
                    # This method must only be called here,
                    # otherwise we can end up with extra untracked mapping tuples.
                    mapping = create_default_mapping_for_system_role(v2_resource)
                    mapping.save(force_insert=True)
