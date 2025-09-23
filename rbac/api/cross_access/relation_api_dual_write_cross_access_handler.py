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

from django.db import transaction
from management.group.relation_api_dual_write_subject_handler import RelationApiDualWriteSubjectHandler
from management.models import Principal, Workspace
from management.principal.v2_model import RoleBindingPrincipal
from management.relation_replicator.relation_replicator import (
    DualWriteException,
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.role.model import BindingMapping, Role, SourceKey
from management.role.v2_model import RoleV2, RoleBinding

from api.cross_access.util import create_cross_principal, get_cross_principal_name
from api.models import CrossAccountRequest, Tenant

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

    def generate_relations_to_add_roles(self, roles: Iterable[Role]):
        """Generate relations to add roles."""
        if not self.replication_enabled():
            return
        source_key = SourceKey(self.cross_account_request, self.cross_account_request.source_pk())
        user_id = str(self.cross_account_request.user_id)

        def add_principal_to_binding(mapping: BindingMapping):
            self.relations_to_add.append(mapping.assign_user_to_bindings(user_id, source_key))

        for role in roles:
            self._update_mapping_for_system_role(
                role,
                update_mapping=add_principal_to_binding,
                create_default_mapping_for_system_role=lambda: self._create_default_mapping_for_system_role(
                    role, users={str(source_key): user_id}
                ),
            )
        
        # V2 models are created in _create_default_mapping_for_system_role when needed

    def generate_relations_reset_roles(self, roles: Iterable[Role]):
        """Generate relations to add roles."""
        if not self.replication_enabled():
            return
        source_key = SourceKey(self.cross_account_request, self.cross_account_request.source_pk())
        user_id = str(self.cross_account_request.user_id)

        def add_principal_to_binding(mapping: BindingMapping):
            mapping.update_data_format_for_user(self.relations_to_remove)
            self.relations_to_add.append(mapping.assign_user_to_bindings(user_id, source_key))

        for role in roles:
            self._update_mapping_for_system_role(
                role,
                update_mapping=add_principal_to_binding,
                create_default_mapping_for_system_role=lambda: self._create_default_mapping_for_system_role(
                    role, users={str(source_key): user_id}
                ),
            )
        
        # V2 models are created in _create_default_mapping_for_system_role when needed

    def replicate(self):
        """Replicate generated relations."""
        if not self.replication_enabled():
            return

        self._replicate()

    def generate_relations_to_remove_roles(self, roles: Iterable[Role]):
        """Generate relations to remove roles."""
        if not self.replication_enabled():
            return
        source_key = SourceKey(self.cross_account_request, self.cross_account_request.source_pk())
        user_id = str(self.cross_account_request.user_id)

        def remove_principal_from_binding(mapping: BindingMapping):
            removal = mapping.unassign_user_from_bindings(user_id, source=source_key)
            if removal is not None:
                self.relations_to_remove.append(removal)

        for role in roles:
            self._update_mapping_for_system_role(
                role, update_mapping=remove_principal_from_binding, create_default_mapping_for_system_role=None
            )
        
        # V2 model removal handled separately if needed

    def _get_cross_account_principal(self, target_tenant: Tenant) -> Principal:
        """Get the cross-account principal for the request (assumes already created)."""
        principal_name = get_cross_principal_name(
            self.cross_account_request.target_org, 
            str(self.cross_account_request.user_id)
        )
        
        try:
            principal = Principal.objects.get(username=principal_name, tenant=target_tenant)
            return principal
        except Principal.DoesNotExist:
            logger.error(f"Cross-account principal {principal_name} not found for request {self.cross_account_request.request_id}")
            raise

    def _get_role_v2_from_v1_role(self, v1_role: Role, target_tenant: Tenant) -> RoleV2:
        """Get RoleV2 from V1 Role (assumes already exists)."""
        try:
            role_v2 = RoleV2.objects.get(name=v1_role.name, tenant=target_tenant)
            return role_v2
        except RoleV2.DoesNotExist:
            logger.error(f"RoleV2 {v1_role.name} not found for tenant {target_tenant.org_id} and V1 role {v1_role.uuid}")
            raise

    def _get_or_create_role_binding(self, role_v2: RoleV2, target_tenant: Tenant, resource_type: str = "workspace", resource_id: str = None) -> RoleBinding:
        """Get or create RoleBinding for the given RoleV2."""
        if resource_id is None:
            resource_id = str(self.workspace.id)
            
        role_binding, created = RoleBinding.objects.get_or_create(
            role=role_v2,
            resource_type=resource_type,
            resource_id=resource_id,
            tenant=target_tenant,
        )
        
        if created:
            logger.info(f"Created RoleBinding {role_binding.uuid} for role {role_v2.uuid}")
            
        return role_binding

    def _create_role_binding_principal(self, principal: Principal, role_binding: RoleBinding, source: str, target_tenant: Tenant) -> RoleBindingPrincipal:
        """Create RoleBindingPrincipal association."""
        role_binding_principal, created = RoleBindingPrincipal.objects.get_or_create(
            principal=principal,
            binding=role_binding,
            source=source,
            tenant=target_tenant,
        )
        
        if created:
            logger.info(f"Created RoleBindingPrincipal for principal {principal.uuid} and binding {role_binding.uuid}")
            
        return role_binding_principal


    def _create_default_mapping_for_system_role(self, system_role: Role, **subject) -> BindingMapping:
        """Create default mapping and complete V2 model creation for cross-account roles."""
        from uuid import uuid4
        from migration_tool.models import V2rolebinding, V2role, V2boundresource
        
        assert system_role.system is True, "Expected system role. Mappings for custom roles must already be created."
        
        # Get target tenant for V2 models
        target_tenant = Tenant.objects.get(org_id=self.cross_account_request.target_org)
        
        # Create V1 BindingMapping
        binding = V2rolebinding(
            str(uuid4()),
            # Assumes same role UUID for V2 system role equivalent.
            V2role.for_system_role(str(system_role.uuid)),
            V2boundresource(("rbac", "workspace"), str(self.workspace.id)),
            **subject,
        )
        mapping = BindingMapping.for_role_binding(binding, system_role)
        self.relations_to_add.extend(mapping.as_tuples())
        
        # Create complete V2 model stack (RoleV2, RoleBinding, RoleBindingPrincipal)
        try:
            # Get cross-account principal (already created during approval)
            principal = self._get_cross_account_principal(target_tenant)
            source_key = str(SourceKey(self.cross_account_request, self.cross_account_request.source_pk()))
            
            # Get RoleV2 from V1 role (already exists)
            role_v2 = self._get_role_v2_from_v1_role(system_role, target_tenant)
            
            # Get or create RoleBinding
            role_binding = self._get_or_create_role_binding(role_v2, target_tenant)
            
            # Create RoleBindingPrincipal association
            self._create_role_binding_principal(principal, role_binding, source_key, target_tenant)
            
            logger.info(f"Created complete V2 model stack for system role {system_role.name} during default mapping creation")
        except Exception as e:
            logger.error(f"Error creating V2 models for system role {system_role.name}: {e}")
            # Don't raise here - the BindingMapping was created successfully
        
        return mapping
