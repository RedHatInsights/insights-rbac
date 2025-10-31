#
# Copyright 2025 Red Hat, Inc.
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

"""Inventory API client utilities for gRPC communication."""

from contextlib import contextmanager

from kessel.inventory.v1beta2 import (
    inventory_service_pb2_grpc,
    reporter_reference_pb2,
    resource_reference_pb2,
    subject_reference_pb2,
)
from management.utils import create_client_channel_inventory


def make_resource_ref(resource_type: str, resource_id: str, reporter_type: str = "rbac"):
    """
    Create a resource reference for the given type and ID.

    Args:
        resource_type: Type of resource (e.g., "workspace", "principal")
        resource_id: Unique identifier for the resource
        reporter_type: Type of reporter (defaults to "rbac")

    Returns:
        ResourceReference: The protobuf resource reference
    """
    reporter = reporter_reference_pb2.ReporterReference(type=reporter_type)
    return resource_reference_pb2.ResourceReference(
        resource_type=resource_type,
        resource_id=resource_id,
        reporter=reporter,
    )


def make_subject_ref(principal_id: str):
    """
    Create a subject reference for a principal.

    Args:
        principal_id: Principal identifier (e.g., "localhost/username")

    Returns:
        SubjectReference: The protobuf subject reference for the principal
    """
    # Principal is represented as a ResourceReference under the hood
    return subject_reference_pb2.SubjectReference(resource=make_resource_ref("principal", principal_id))


@contextmanager
def inventory_client(server_address: str):
    """
    Context manager for Inventory API gRPC client.

    Args:
        server_address: The Inventory API server address

    Yields:
        KesselInventoryServiceStub: The gRPC stub for making API calls
    """
    with create_client_channel_inventory(server_address) as channel:
        yield inventory_service_pb2_grpc.KesselInventoryServiceStub(channel)
