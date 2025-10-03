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
"""Contains a command to update the V2 parent relations for seeded roles to match their expected scope."""
from django.conf import settings
from django.core.management import BaseCommand
from kessel.relations.v1beta1.common_pb2 import Relationship
from management.group.platform import GlobalPolicyIdService
from management.models import Role
from management.permission.scope_service import ImplicitResourceService, Scope
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    PartitionKey,
    ReplicationEvent,
    ReplicationEventType,
)
from migration_tool.utils import create_relationship


def _child_relationship(parent_uuid: str, child_uuid: str) -> Relationship:
    return create_relationship(
        resource_name=("rbac", "role"),
        resource_id=parent_uuid,
        subject_name=("rbac", "role"),
        subject_id=child_uuid,
        relation="child",
    )


class Command(BaseCommand):
    """Command to update the V2 parent relations for seeded roles to match their expected scope."""

    help = "Update the V2 parent relations for seeded roles to match their expected scope"

    def handle(self, *args, **options):
        """
        Update the V2 relations for system roles to reflect the appropriate scope based on their permissions.

        This will not correctly handle any roles that have changed since the last time system roles were replicated to
        relations (with seed_roles and REPLICATION_TO_RELATION_ENABLED=True).

        replicator defaults to an OutboxReplicator.
        resource_service defaults to ImplicitResourceService.from_settings().
        """
        replicator = OutboxReplicator()
        resource_service = ImplicitResourceService.from_settings()

        # Removing relations happens before adding them, so having the same relation in both lists is fine,
        # and the relation will end up being present. This means we can remove the existing relations without
        # worrying about whether we'll immediately add them back.
        relations_to_remove: list[Relationship] = []
        relations_to_add: list[Relationship] = []

        policy_cache = GlobalPolicyIdService()

        platform_default_uuid = str(policy_cache.platform_default_policy_uuid())
        admin_default_uuid = str(policy_cache.admin_default_policy_uuid())

        platform_role_for_scope = {
            Scope.DEFAULT: platform_default_uuid,
            Scope.ROOT: settings.SYSTEM_DEFAULT_ROOT_WORKSPACE_ROLE_UUID,
            Scope.TENANT: settings.SYSTEM_DEFAULT_TENANT_ROLE_UUID,
        }

        admin_role_for_scope = {
            Scope.DEFAULT: admin_default_uuid,
            Scope.ROOT: settings.SYSTEM_ADMIN_ROOT_WORKSPACE_ROLE_UUID,
            Scope.TENANT: settings.SYSTEM_ADMIN_TENANT_ROLE_UUID,
        }

        for role in Role.objects.public_tenant_only():
            role_uuid = str(role.uuid)
            target_scope = resource_service.highest_scope_for_permissions(
                [a.permission.permission for a in role.access.all()]
            )

            if role.platform_default:
                relations_to_remove.append(
                    _child_relationship(
                        parent_uuid=platform_default_uuid,
                        child_uuid=role_uuid,
                    )
                )

                relations_to_add.append(
                    _child_relationship(
                        parent_uuid=platform_role_for_scope[target_scope],
                        child_uuid=role_uuid,
                    )
                )

            if role.admin_default:
                relations_to_remove.append(
                    _child_relationship(
                        parent_uuid=admin_default_uuid,
                        child_uuid=role_uuid,
                    )
                )

                relations_to_add.append(
                    _child_relationship(
                        parent_uuid=admin_role_for_scope[target_scope],
                        child_uuid=role_uuid,
                    )
                )

        replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.REBIND_SYSTEM_ROLE_SCOPES,
                partition_key=PartitionKey.byEnvironment(),
                remove=relations_to_remove,
                add=relations_to_add,
            )
        )
