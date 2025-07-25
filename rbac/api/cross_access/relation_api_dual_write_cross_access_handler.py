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

from api.cross_access.model import CrossAccountRequestV2
from management.group.relation_api_dual_write_subject_handler import RelationApiDualWriteSubjectHandler
from management.models import Workspace
from management.relation_replicator.relation_replicator import (
    DualWriteException,
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.role.model import BindingMapping, Role, SourceKey, RoleV2

from api.models import CrossAccountRequest, Tenant
from management.role_binding.dual import (
    dual_binding_assign_user,
    dual_binding_unassign_user,
    dual_binding_update_data_format,
)
from management.role_binding.model import RoleBinding

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationApiDualWriteCrossAccessHandler(RelationApiDualWriteSubjectHandler):
    """Class to handle Dual Write for cross account access bindings."""

    def __init__(
        self,
        cross_account_request: CrossAccountRequest,
        event_type: ReplicationEventType,
        replicator: Optional[RelationReplicator] = None,
    ):
        """Initialize RelationApiDualWriteCrossAccessHandler."""
        if not self.replication_enabled():
            return

        try:
            self.cross_account_request = cross_account_request
            tenant = Tenant.objects.get(org_id=self.cross_account_request.target_org)
            default_workspace = Workspace.objects.default(tenant=tenant)
            super().__init__(default_workspace, event_type, replicator)
        except Exception as e:
            logger.error(
                f"Error initializing RelationApiDualWriteCrossAccessHandler for request id: "
                f"{self.cross_account_request.request_id}"
            )

            raise DualWriteException(e)

    def _replicate(self):
        if not self.replication_enabled():
            return
        try:
            self._replicator.replicate(
                ReplicationEvent(
                    event_type=self.event_type,
                    info={
                        "user_id": str(self.cross_account_request.user_id),
                        "roles": [role.uuid for role in self.cross_account_request.roles.all()],
                        "target_org": self.cross_account_request.target_org,
                    },
                    partition_key=PartitionKey.byEnvironment(),
                    remove=self.relations_to_remove,
                    add=self.relations_to_add,
                ),
            )
        except Exception as e:
            logger.error("Error occurred in cross account replicate event", e)
            raise DualWriteException(e)

    def _update_v2_model(self):
        v2_request, _ = CrossAccountRequestV2.objects.update_or_create(
            request_id=self.cross_account_request.request_id,
            defaults={
                "target_account": self.cross_account_request.target_account,
                "target_org": self.cross_account_request.target_org,
                "user_id": self.cross_account_request.user_id,
                "created": self.cross_account_request.created,
                "start_date": self.cross_account_request.start_date,
                "end_date": self.cross_account_request.end_date,
                "modified": self.cross_account_request.modified,
                "status": self.cross_account_request.status,
                "target_resource_type_namespace": "rbac",
                "target_resource_type_name": "workspace",
                "target_resource_id": self.default_workspace.id,
            },
        )

        # We assume that system roles are one-to-one between V1 and V2.
        # TODO: this is inefficient, but I want to lazily verify the assertion that the roles are actually one-to-one.
        v2_request.roles.set(
            [RoleV2.objects.filter(v1_source=v1_role).get() for v1_role in self.cross_account_request.roles.all()]
        )

    def generate_relations_to_add_roles(self, roles: Iterable[Role]):
        """Generate relations to add roles."""
        if not self.replication_enabled():
            return
        source_key = SourceKey(self.cross_account_request, self.cross_account_request.source_pk())
        user_id = str(self.cross_account_request.user_id)

        def add_principal_to_binding(mapping: BindingMapping, role_binding: RoleBinding):
            self.relations_to_add.append(
                dual_binding_assign_user(mapping, role_binding, user_id=user_id, source=source_key)
            )

        for role in roles:
            self._update_mapping_for_system_role(
                role,
                update_mapping=add_principal_to_binding,
                create_default_mapping_for_system_role=lambda: self._create_default_mapping_for_system_role(
                    role, users={str(source_key): user_id}
                ),
            )

    def generate_relations_reset_roles(self, roles: Iterable[Role]):
        """Generate relations to add roles."""
        if not self.replication_enabled():
            return
        source_key = SourceKey(self.cross_account_request, self.cross_account_request.source_pk())
        user_id = str(self.cross_account_request.user_id)

        def add_principal_to_binding(mapping: BindingMapping, role_binding: RoleBinding):
            dual_binding_update_data_format(mapping, role_binding, self.relations_to_remove)
            self.relations_to_add.append(
                dual_binding_assign_user(mapping, role_binding, user_id=user_id, source=source_key)
            )

        for role in roles:
            self._update_mapping_for_system_role(
                role,
                update_mapping=add_principal_to_binding,
                create_default_mapping_for_system_role=lambda: self._create_default_mapping_for_system_role(
                    role, users={str(source_key): user_id}
                ),
            )

    def replicate(self):
        """Replicate generated relations."""
        if not self.replication_enabled():
            return

        # TODO: replicate is not called every time a cross-account request is updated, so this won't actually keep
        # the models in sync.
        self._update_v2_model()
        self._replicate()

    def generate_relations_to_remove_roles(self, roles: Iterable[Role]):
        """Generate relations to remove roles."""
        if not self.replication_enabled():
            return
        source_key = SourceKey(self.cross_account_request, self.cross_account_request.source_pk())
        user_id = str(self.cross_account_request.user_id)

        def remove_principal_from_binding(mapping: BindingMapping, role_binding: RoleBinding):
            removal = dual_binding_unassign_user(mapping, role_binding, user_id=user_id, source=source_key)
            if removal is not None:
                self.relations_to_remove.append(removal)

        for role in roles:
            self._update_mapping_for_system_role(
                role, update_mapping=remove_principal_from_binding, create_default_mapping_for_system_role=None
            )
