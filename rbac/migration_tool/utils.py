"""Utilities for working with the relation API server."""
import logging

import grpc
from django.conf import settings
from kessel.relations.v1beta1 import common_pb2
from kessel.relations.v1beta1 import relation_tuples_pb2
from kessel.relations.v1beta1 import relation_tuples_pb2_grpc
from protoc_gen_validate.validator import ValidationFailed, validate_all


logger = logging.getLogger(__name__)


def validate_and_create_obj_ref(obj_name, obj_id):
    """Validate and create a resource."""
    object_type = common_pb2.ObjectType(name=obj_name)
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


def create_relationship(resource_name, resource_id, subject_name, subject_id, relation):
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
            logger.error(
                "Failed to write relationships to the relation API server: "
                f"error code {err.code()}, reason {err.details()}"
                f"relationships: {relationships}"
            )
