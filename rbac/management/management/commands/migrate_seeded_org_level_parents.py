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
import logging

from django.core.management import BaseCommand
from django.db.models import Q
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
from management.role.platform import platform_v2_role_uuid_for
from management.role.relations import role_child_relationship
from management.tenant_mapping.model import DefaultAccessType

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


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

        policy_service = GlobalPolicyIdService()

        for role in Role.objects.public_tenant_only().filter(Q(platform_default=True) | Q(admin_default=True)):
            target_scope = resource_service.highest_scope_for_permissions(
                [a.permission.permission for a in role.access.all()]
            )

            role_desc = f"{repr(role.name)} (id={role.id})"

            # Remove any existing parent-child relations with both platform- and admin-default roles.
            for access_type in DefaultAccessType:
                for scope in Scope:
                    relations_to_remove.append(
                        role_child_relationship(
                            parent_uuid=platform_v2_role_uuid_for(access_type, scope, policy_service=policy_service),
                            child_uuid=role.uuid,
                        )
                    )

            if role.platform_default:
                logger.info(
                    f"Rebinding role {role_desc} to have platform-default parent role for scope {target_scope.name}."
                )

                relations_to_add.append(
                    role_child_relationship(
                        parent_uuid=platform_v2_role_uuid_for(
                            DefaultAccessType.USER,
                            target_scope,
                            policy_service=policy_service,
                        ),
                        child_uuid=role.uuid,
                    )
                )

            if role.admin_default:
                logger.info(
                    f"Rebinding role {role_desc} to have admin-default parent role for scope {target_scope.name}."
                )

                relations_to_add.append(
                    role_child_relationship(
                        parent_uuid=platform_v2_role_uuid_for(
                            DefaultAccessType.ADMIN,
                            target_scope,
                            policy_service=policy_service,
                        ),
                        child_uuid=role.uuid,
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
