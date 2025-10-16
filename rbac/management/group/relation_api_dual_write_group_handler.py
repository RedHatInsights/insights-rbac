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

from kessel.relations.v1beta1.common_pb2 import Relationship
from management.group.model import Group
from management.group.platform import GlobalPolicyIdService
from management.group.relation_api_dual_write_subject_handler import RelationApiDualWriteSubjectHandler
from management.models import Workspace
from management.permission.scope_service import (
    ImplicitResourceService,
    Scope,
    TenantScopeResources,
)
from management.principal.model import Principal
from management.relation_replicator.relation_replicator import (
    DualWriteException,
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.role.model import BindingMapping, Role
from management.tenant_mapping.model import DefaultAccessType, TenantMapping
from management.tenant_service.relations import default_role_binding_tuples

from api.models import Tenant

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationApiDualWriteGroupHandler(RelationApiDualWriteSubjectHandler):
    """Class to handle Dual Write for group bindings and membership."""

    group: Group
    _expected_empty_relation_reason = None
    _policy_service: GlobalPolicyIdService
    _resource_service: ImplicitResourceService

    def __init__(
        self,
        group,
        event_type: ReplicationEventType,
        replicator: Optional[RelationReplicator] = None,
        resource_service: Optional[ImplicitResourceService] = None,
    ):
        """Initialize RelationApiDualWriteGroupHandler."""
        if not self.replication_enabled():
            return

        try:
            self.group = group
            self.principals = []
            self._platform_default_policy_uuid: Optional[str] = None
            self._public_tenant: Optional[Tenant] = None
            self._tenant_mapping = None
            self._policy_service = GlobalPolicyIdService.shared()

            if resource_service is not None:
                self._resource_service = resource_service
            else:
                self._resource_service = ImplicitResourceService.from_settings()

            tenant = Tenant.objects.get(id=self.group.tenant_id)
            default_workspace = Workspace.objects.default(tenant=tenant)
            root_workspace = Workspace.objects.root(tenant=tenant)

            super().__init__(
                tenant=tenant,
                default_workspace=default_workspace,
                root_workspace=root_workspace,
                event_type=event_type,
                replicator=replicator,
            )
        except Exception as e:
            logger.error(f"Initialization of RelationApiDualWriteGroupHandler failed: {e}")
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
        logger.info("[Dual Write] Replicate new principals into Group(%s):, '%s'", self.group.uuid, self.group.name)
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
            logger.error(f"Replication event failed for group: {self.group.uuid}: {e}")
            raise DualWriteException(e)

    def _can_use_non_default_scope(self):
        """
        Determine whether it is possible to bind roles in non-default scopes for this replicator's group.

        Over time, this must never be changed to return false for a group for which it has previously returned true.
        For example, this could result in a role being bound in the tenant scope while this method returns true,
        then later (when this method returns false) attempting to remove the role but not attempting to unbind the
        role from tenant scope.
        """
        return self.group.platform_default or self.group.admin_default

    def _generate_add_relations(
        self,
        roles: Iterable[Role],
        scope_fn: Callable[[Role], Scope],
        remove_default_access_from: Optional[TenantMapping] = None,
    ):
        if not self.replication_enabled():
            return

        def reset_mapping(mapping: BindingMapping):
            to_remove = mapping.unassign_group(str(self.group.uuid))
            if to_remove:
                self.relations_to_remove.append(to_remove)
            to_add = mapping.assign_group_to_bindings(str(self.group.uuid))
            if to_add:
                self.relations_to_add.append(to_add)

        allow_non_default = self._can_use_non_default_scope()

        # Go through current roles
        # For each binding
        # Remove all of this subject
        # Replicate this removal
        # Add back subject
        # Replicate this addition
        for role in roles:
            # Note that we do not attempt to handle the case where the scope has changed. At time of writing
            # (2025-10-08), this case is expected to be handled during seeding for system roles. It is unclear how
            # custom roles should be handled.
            scope = scope_fn(role)

            # We do not currently support binding non-system roles in non-default scope. Currently (2025-10-08),
            # only certain groups (platform-/admin-default groups) can have role bindings in non-default scope. For
            # system roles, this isn't a problem: we can simply bind the group to the system role in the role binding
            # for the appropriate scope.
            #
            # For custom roles, however, this isn't so simple. Custom roles in V1 can become multiple roles in V2 due
            # to resource definitions, where each V2 role has a different set of permissions (based on all possible
            # sets of permissions the V1 role could result in); each applicable resource (along with the default
            # workspace) is then given its own role binding using the V2 role with the appropriate permissions.
            # Various code (including this method) assumes that adding a group to each role binding for a custom V1
            # role is sufficient to grant that role to the group, and thus each role binding for a V1 role has the
            # same set of groups. If only *some* groups could be assigned in non-default scope, this assumption would
            # be violated. See v1_role_to_v2_bindings for another example of what goes wrong if we try to do that.
            # (This issue does not arise for system roles, since no such assumption is made; we can always identify a
            # specific BindingMapping to modify given a system role, its scope, and the tenant to bind it in.)
            if scope != Scope.DEFAULT:
                assert allow_non_default
                assert role.system

            self._update_mapping_for_role(
                role,
                scope=scope,
                update_mapping=reset_mapping,
                create_default_mapping_for_system_role=lambda resource: self._create_default_mapping_for_system_role(
                    system_role=role,
                    resource=resource,
                    groups=frozenset([str(self.group.uuid)]),
                ),
            )

        if remove_default_access_from is not None:
            self.relations_to_remove.extend(
                self._default_binding(resource_binding_only=True, mapping=remove_default_access_from)
            )

    def generate_relations_reset_roles(
        self, roles: Iterable[Role], remove_default_access_from: Optional[TenantMapping] = None
    ):
        """
        Reset the mapping and relationships for the group, assuming this group should only be assigned once.

        This is safe if you are SURE this group should only be assigned once,
        OR you will be re-adding the other sources of assignments.

        This method **IS** idempotent. It will reset the group to the same state every time.
        """
        return self._generate_add_relations(
            roles=roles,
            scope_fn=lambda role: Scope.DEFAULT,
            remove_default_access_from=remove_default_access_from,
        )

    def generate_relations_scoped_reset_roles(
        self, roles: Iterable[Role], remove_default_access_from: Optional[TenantMapping] = None
    ):
        """
        Replicate the addition of the provided roles to the group while respecting role scope.

        This functions just as generate_relations_reset_roles, except that the implicit scope of the roles is
        considered when generating role bindings.

        This currently only works for platform-/admin- default groups and system roles.
        """
        roles = list(roles)

        if not self._can_use_non_default_scope():
            raise ValueError("Non-default scopes are not supported for this group.")

        if not all(role.system for role in roles):
            raise ValueError("Adding roles in non-default scope is supported only for system roles.")

        return self._generate_add_relations(
            roles=roles,
            scope_fn=self._resource_service.scope_for_role,
            remove_default_access_from=remove_default_access_from,
        )

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
            removal = mapping.pop_group_from_bindings(str(self.group.uuid))
            if removal is not None:
                self.relations_to_remove.append(removal)

        def do_update(scope: Scope):
            self._update_mapping_for_role(
                role,
                scope=scope,
                update_mapping=remove_group_from_binding,
                create_default_mapping_for_system_role=None,
            )

        if self._can_use_non_default_scope():
            # If the role could be bound to a non-default scope, we have to handle two cases:
            # * An existing role binding that has not been migrated. Here, the role would still be bound in the
            #   default workspace, and we have to remove it from there.
            # * A role binding that has been migrated, or a role binding that was added after scope started being
            #   respected. Here, we have to remove it from the correct scope.
            # We could even have both, if a new role binding is created while scope is being respected but before the
            # old role bindings have been pruned. We have no a priori way to distinguish between these two cases,
            # so we always have to check at least the default workspace and the correct resource.
            #
            # In order to handle both cases (as well as the case where the scope of the role has changed since it was
            # assigned), always attempt to remove the role from all scopes.
            for scope in Scope:
                do_update(scope)
        else:
            do_update(Scope.DEFAULT)

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
            # If we are restoring the default role binding, we need to handle the case where *none* of the
            # relationships exist. This can happen if we bootstrapped a tenant that already had a custom default
            # group (in which case V2TenantBootstrapService will indeed refuse to create a default role binding at all),
            # and now we are removing that custom default group.
            self.relations_to_add.extend(self._default_binding(resource_binding_only=False))
        else:
            self.principals = self.group.principals.all()
            self.relations_to_remove.extend(self._generate_member_relations())

    def _default_binding(
        self,
        resource_binding_only: bool,
        mapping: Optional[TenantMapping] = None,
    ) -> list[Relationship]:
        """
        Calculate default bindings from tenant mapping.

        resource_binding_only has the same meaning as in default_role_binding_tuples. It should be set to True when
        calculating the tuples to remove. (Note that this occurs when handling the *addition* of a custom default group,
        since that is when the default role binding is unbound.)
        """
        if mapping is None:
            mapping = TenantMapping.objects.get(tenant=self.group.tenant)
        else:
            assert mapping.tenant.id == self.group.tenant_id, "Tenant mapping does not match group tenant."

        return default_role_binding_tuples(
            tenant_mapping=mapping,
            target_resources=TenantScopeResources.for_models(
                tenant=self.group.tenant,
                root_workspace=self.root_workspace,
                default_workspace=self.default_workspace,
            ),
            access_type=DefaultAccessType.USER,
            resource_binding_only=resource_binding_only,
            policy_service=self._policy_service,
        )

    def set_expected_empty_relation_reason(self, reason):
        """Set expected empty relation reason."""
        self._expected_empty_relation_reason = reason
