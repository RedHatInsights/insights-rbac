"""RelationReplicator which writes to the outbox table."""

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


class SyncReplicator(RelationReplicator):
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
