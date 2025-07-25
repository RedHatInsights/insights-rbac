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
from django.conf import settings
from google.protobuf import json_format
from google.rpc import error_details_pb2
from grpc import RpcError
from grpc_status import rpc_status
from kessel.relations.v1beta1 import check_pb2
from kessel.relations.v1beta1 import check_pb2_grpc
from kessel.relations.v1beta1 import common_pb2
from management.cache import JWTCache
from management.jwt import JWTManager, JWTProvider
from management.relation_replicator.relation_replicator import RelationReplicator
from management.utils import create_client_channel

jwt_cache = JWTCache()
jwt_provider = JWTProvider()
jwt_manager = JWTManager(jwt_provider, jwt_cache)
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationsApiRelationChecker(RelationReplicator):
    """Checks relations via the Relations API over gRPC."""

    def replicate(self, relationships):
        """Replicate the given event to Kessel Relations via the gRPC API."""
        assignments = self._check_relationships(relationships=relationships)
        return assignments

    def _check_relationships(self, relationships):
        relations_assignments = {"group_uuid": "", "principal_relations": []}
        for r in relationships:
            relation_exists = self.check_relation_core(r)
            relations_assignments["group_uuid"] = r.resource.id
            relations_assignments["principal_relations"].append(
                {"id": r.subject.subject.id, "relation_exists": relation_exists}
            )
            if not relation_exists:
                logger.warning(
                    f"Relation missing: User ID {r.subject.subject.id} is not associated with Group ID {r.resource.id}"
                )
        return relations_assignments


    def check_relation_core(self, r: common_pb2.Relationship) -> bool:
        """
        Core function to check relation between a resource and a subject using gRPC.

        Returns True if relation exists, False otherwise.
        """
        token = jwt_manager.get_jwt_from_redis()
        try:
            with create_client_channel(settings.RELATION_API_SERVER) as channel:
                stub = check_pb2_grpc.KesselCheckServiceStub(channel)

                request_data = check_pb2.CheckRequest(
                    resource=common_pb2.ObjectReference(
                        type=common_pb2.ObjectType(namespace=r.resource.type.namespace, name=r.resource.type.name),
                        id=r.resource.id,
                    ),
                    relation=r.relation,
                    subject=common_pb2.SubjectReference(
                        relation=r.subject.relation,
                        subject=common_pb2.ObjectReference(
                            type=common_pb2.ObjectType(
                                namespace=r.subject.subject.type.namespace, name=r.subject.subject.type.name
                            ),
                            id=r.subject.subject.id,
                        ),
                    ),
                )

                metadata = [("authorization", f"Bearer {token}")]
                response = stub.Check(request_data, metadata=metadata)

                if response:
                    response_dict = json_format.MessageToDict(response)
                    return response_dict.get("allowed", "") != "ALLOWED_FALSE"

        except RpcError as e:
            logger.error(f"[gRPC] check_relation failed: {e}")
        except Exception as e:
            logger.error(f"[Unexpected] check_relation failed: {e}")
        return False

