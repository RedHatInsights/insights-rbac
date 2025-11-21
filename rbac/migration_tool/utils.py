"""Utilities for working with the relation API server."""

import logging
from typing import Optional, Tuple

from kessel.relations.v1beta1 import common_pb2
from protoc_gen_validate.validator import ValidationFailed, validate_all


logger = logging.getLogger(__name__)


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
    resource_name: Tuple[str, str],
    resource_id: str,
    subject_name: Tuple[str, str],
    subject_id: str,
    relation: str,
    subject_relation: Optional[str] = None,
):
    """Create a relationship between a resource and a subject."""
    # Validation gate: Ensure no None or empty values in IDs
    if resource_id is None or resource_id == "":
        raise ValueError(
            f"Cannot create relationship with None or empty resource_id. "
            f"Resource: {resource_name}, Subject: {subject_name}, Subject ID: {subject_id}, Relation: {relation}. "
        )
    if subject_id is None or subject_id == "":
        raise ValueError(
            f"Cannot create relationship with None or empty subject_id. "
            f"Resource: {resource_name}, Resource ID: {resource_id}, Subject: {subject_name}, Relation: {relation}. "
        )

    return common_pb2.Relationship(
        resource=validate_and_create_obj_ref(resource_name, resource_id),
        relation=relation,
        subject=common_pb2.SubjectReference(
            subject=validate_and_create_obj_ref(subject_name, subject_id), relation=subject_relation
        ),
    )
