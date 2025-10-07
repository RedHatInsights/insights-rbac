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
from management.tenant_mapping.model import DefaultAccessType
from migration_tool.utils import create_relationship

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


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

        policy_service = GlobalPolicyIdService()

        platform_default_uuid = str(
            platform_v2_role_uuid_for(DefaultAccessType.USER, Scope.DEFAULT, policy_service=policy_service)
        )

        admin_default_uuid = str(
            platform_v2_role_uuid_for(DefaultAccessType.ADMIN, Scope.DEFAULT, policy_service=policy_service)
        )

        for role in Role.objects.public_tenant_only().filter(Q(platform_default=True) | Q(admin_default=True)):
            role_uuid = str(role.uuid)
            target_scope = resource_service.highest_scope_for_permissions(
                [a.permission.permission for a in role.access.all()]
            )

            role_desc = f"{repr(role.name)} (id={role.id})"

            if role.platform_default:
                logger.info(
                    f"Rebinding role {role_desc} to have platform-default parent role for scope {target_scope.name}."
                )

                relations_to_remove.append(
                    _child_relationship(
                        parent_uuid=platform_default_uuid,
                        child_uuid=role_uuid,
                    )
                )

                relations_to_add.append(
                    _child_relationship(
                        parent_uuid=str(
                            platform_v2_role_uuid_for(
                                DefaultAccessType.USER, target_scope, policy_service=policy_service
                            )
                        ),
                        child_uuid=role_uuid,
                    )
                )

            if role.admin_default:
                logger.info(
                    f"Rebinding role {role_desc} to have admin-default parent role for scope {target_scope.name}."
                )

                relations_to_remove.append(
                    _child_relationship(
                        parent_uuid=admin_default_uuid,
                        child_uuid=role_uuid,
                    )
                )

                relations_to_add.append(
                    _child_relationship(
                        parent_uuid=str(
                            platform_v2_role_uuid_for(
                                DefaultAccessType.ADMIN, target_scope, policy_service=policy_service
                            )
                        ),
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
