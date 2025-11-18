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

"""RelationReplicator which writes to the Relations API."""

import json
import logging


import grpc
from django.conf import settings
from google.rpc import error_details_pb2
from grpc_status import rpc_status
from kessel.relations.v1beta1 import relation_tuples_pb2
from kessel.relations.v1beta1 import relation_tuples_pb2_grpc
from management.relation_replicator.relation_replicator import RelationReplicator, ReplicationEvent


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class RelationsApiReplicator(RelationReplicator):
    """Replicates relations via the Relations API over gRPC."""

    def replicate(self, event: ReplicationEvent):
        """Replicate the given event to Kessel Relations via the gRPC API."""
        self._write_relationships(event.add)

    def _write_relationships(self, relationships):
        with grpc.insecure_channel(settings.RELATION_API_SERVER) as channel:
            stub = relation_tuples_pb2_grpc.KesselTupleServiceStub(channel)

            request = relation_tuples_pb2.CreateTuplesRequest(
                upsert=True,
                tuples=relationships,
            )
            try:
                return stub.CreateTuples(request)
            except grpc.RpcError as err:
                error = GRPCError(err)
                logger.error(
                    "Failed to write relationships to the relation API server: "
                    f"error code {error.code}, reason {error.reason}"
                    f"relationships: {relationships}"
                )
                raise

    def _delete_relationships(self, relationships):
        """Delete relationships using the new filter-based API.

        For each relationship, create a filter that matches it exactly and delete it.
        """
        # If no relationships to delete, return an empty response
        if not relationships:
            logger.debug("No relationships to delete, returning empty response")
            # Return a mock response with empty consistency token
            return type("obj", (object,), {"consistency_token": type("obj", (object,), {"token": None})()})()

        with grpc.insecure_channel(settings.RELATION_API_SERVER) as channel:
            stub = relation_tuples_pb2_grpc.KesselTupleServiceStub(channel)

            # Delete each relationship individually using filters
            responses = []
            for relationship in relationships:
                # Create a filter that matches this specific relationship
                relation_filter = relation_tuples_pb2.RelationTupleFilter(
                    resource_namespace=relationship.resource.type.namespace,
                    resource_type=relationship.resource.type.name,
                    resource_id=relationship.resource.id,
                    relation=relationship.relation,
                    subject_filter=relation_tuples_pb2.SubjectFilter(
                        subject_namespace=relationship.subject.subject.type.namespace,
                        subject_type=relationship.subject.subject.type.name,
                        subject_id=relationship.subject.subject.id,
                        relation=relationship.subject.relation if relationship.subject.relation else "",
                    ),
                )

                request = relation_tuples_pb2.DeleteTuplesRequest(
                    filter=relation_filter,
                )
                try:
                    response = stub.DeleteTuples(request)
                    responses.append(response)
                except grpc.RpcError as err:
                    error = GRPCError(err)
                    logger.error(
                        "Failed to delete relationship from the relation API server: "
                        f"error code {error.code}, reason {error.reason}, "
                        f"relationship: {relationship}"
                    )
                    raise

            # Return the last response (for consistency token)
            return responses[-1] if responses else None


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
        self.reason = "unknown"
        self.metadata = {}

        try:
            status = rpc_status.from_call(error)
            if status is not None and status.details:
                detail = status.details[0]
                info = error_details_pb2.ErrorInfo()
                detail.Unpack(info)
                self.reason = info.reason
                self.metadata = json.loads(str(info.metadata).replace("'", '"'))
        except Exception as e:
            logger.debug(f"Could not extract error details: {e}")
