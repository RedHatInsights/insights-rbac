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

"""RelationReplicator which check relations on Relations API."""

import json
import logging


import grpc
from google.rpc import error_details_pb2
from grpc_status import rpc_status
from internal.utils import check_relation_core
from management.relation_replicator.relation_replicator import RelationReplicator

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationsApiAssignmentCheck(RelationReplicator):
    """Checks relations via the Relations API over gRPC."""

    def replicate(self, group, group_uuid, principals, token):
        """Replicate the given event to Kessel Relations via the gRPC API."""
        self.group = group
        self.principals = principals
        relations = self._generate_member_relations()
        assignments = self._check_relationships(group_uuid, relations, token)
        return assignments

    def _check_relationships(self, group_uuid, relationships, token):
        relations_assignments = {"group_uuid": group_uuid, "principal_relations": []}
        for r in relationships:
            subject_id = r.subject.subject.id
            resource_uuid = r.resource.id
            relation_exists = check_relation_core(
                resource_id=resource_uuid,
                resource_name="group",
                resource_namespace="rbac",
                relation="member",
                subject_id=subject_id,
                subject_name="principal",
                subject_namespace="rbac",
                subject_relation=None,
                token=token,
            )
            relations_assignments["principal_relations"].append({"id": subject_id, "relation_exists": relation_exists})
            if not relation_exists:
                logger.warning("Relations does not exist for this user and role")
        return relations_assignments

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


class GRPCError:
    """A wrapper for a gRPC error."""

    code: grpc.StatusCode
    reason: str
    message: str
    metadata: dict

    def __init__(self, error: grpc.RpcError):
        """Initialize the error."""
        self.code = error.code()
        self.message = error.details()

        status = rpc_status.from_call(error)
        if status is not None:
            detail = status.details[0]
            info = error_details_pb2.ErrorInfo()
            detail.Unpack(info)
            self.reason = info.reason
            self.metadata = json.loads(str(info.metadata).replace("'", '"'))
