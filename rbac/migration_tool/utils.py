"""Utilities for working with the relation API server."""

import json
import logging
from typing import Tuple

import grpc
from django.conf import settings
from google.rpc import error_details_pb2
from grpc_status import rpc_status
from kessel.relations.v1beta1 import common_pb2
from kessel.relations.v1beta1 import relation_tuples_pb2
from kessel.relations.v1beta1 import relation_tuples_pb2_grpc
from protoc_gen_validate.validator import ValidationFailed, validate_all


logger = logging.getLogger(__name__)


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


def validate_and_create_obj_ref(obj_name: Tuple[str, str], obj_id):
    """Validate and create a resource."""
    object_type = common_pb2.ObjectType(name=obj_name[1], namespace=obj_name[0])
    try:
        validate_all(object_type)
    except ValidationFailed as err:
        logger.error(err)
    obj_ref = common_pb2.ObjectReference(type=object_type, id=obj_id)
    try:
        validate_all(obj_ref)
    except ValidationFailed as err:
        logger.error(err)
    return obj_ref


def create_relationship(
    resource_name: Tuple[str, str], resource_id, subject_name: Tuple[str, str], subject_id, relation
):
    """Create a relationship between a resource and a subject."""
    return common_pb2.Relationship(
        resource=validate_and_create_obj_ref(resource_name, resource_id),
        relation=relation,
        subject=common_pb2.SubjectReference(subject=validate_and_create_obj_ref(subject_name, subject_id)),
    )


def write_relationships(relationships):
    """Write relationships to the relation API server."""
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


def stringify_spicedb_relationship(rel: common_pb2.Relationship):
    """Stringify a relationship for logging."""
    return (
        f"{rel.resource.type.name}:{rel.resource.id}#{rel.relation}@{rel.subject.subject.type.name}:"
        f"{rel.subject.subject.id}"
    )


def relationship_to_json(rel):
    """Convert a relationship to a JSON object."""
    return {
        "resource": {"type": rel.resource.type.name, "id": rel.resource.id},
        "relation": rel.relation,
        "subject": {"type": rel.subject.subject.type.name, "id": rel.subject.subject.id},
    }


def output_relationships(relationships: list, write_db: bool):
    """Output relationships to the console and optionally write them to the database."""
    for rel in relationships:
        logger.info(stringify_spicedb_relationship(rel))
    if write_db:
        write_relationships(relationships)
