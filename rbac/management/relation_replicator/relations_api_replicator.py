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
                stub.CreateTuples(request)
            except grpc.RpcError as err:
                error = GRPCError(err.value)
                logger.error(
                    "Failed to write relationships to the relation API server: "
                    f"error code {error.code}, reason {error.reason}"
                    f"relationships: {relationships}"
                )


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
