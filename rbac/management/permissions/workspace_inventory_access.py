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

"""Workspace access checker using Inventory API."""

import logging
from typing import Set

from django.conf import settings
from google.protobuf import json_format
from kessel.inventory.v1beta2 import (
    allowed_pb2,
    check_response_pb2,
    inventory_service_pb2_grpc,
    reporter_reference_pb2,
    representation_type_pb2,
    resource_reference_pb2,
    streamed_list_objects_request_pb2,
    subject_reference_pb2,
)
from kessel.inventory.v1beta2.check_request_pb2 import CheckRequest
from management.utils import create_client_channel_inventory

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def _create_reporter_reference(reporter_type: str = "rbac"):
    """Create a reporter reference for the given type."""
    return reporter_reference_pb2.ReporterReference(type=reporter_type)


def _create_principal_subject_reference(principal_id: str):
    """
    Create a subject reference for a principal.

    Args:
        principal_id: Principal identifier (e.g., "localhost/username")

    Returns:
        SubjectReference: The subject reference for the principal
    """
    return subject_reference_pb2.SubjectReference(
        resource=resource_reference_pb2.ResourceReference(
            resource_id=principal_id,
            resource_type="principal",
            reporter=_create_reporter_reference(),
        )
    )


def _create_workspace_resource_reference(workspace_id: str):
    """
    Create a resource reference for a workspace.

    Args:
        workspace_id: UUID of the workspace

    Returns:
        ResourceReference: The resource reference for the workspace
    """
    return resource_reference_pb2.ResourceReference(
        resource_id=workspace_id,
        resource_type="workspace",
        reporter=_create_reporter_reference(),
    )


class WorkspaceInventoryAccessChecker:
    """Check workspace access using Inventory API."""

    def check_workspace_access(
        self,
        workspace_id: str,
        principal_id: str,
        relation: str,
    ) -> bool:
        """
        Check if a principal has access to a specific workspace using Inventory API Check.

        Args:
            workspace_id: UUID of the workspace to check
            principal_id: Principal identifier (e.g., "localhost/username")
            relation: The relation to check

        Returns:
            bool: True if principal has access, False otherwise
        """
        try:
            with create_client_channel_inventory(
                settings.INVENTORY_API_SERVER
            ) as channel:
                stub = inventory_service_pb2_grpc.KesselInventoryServiceStub(channel)

                check_request = CheckRequest(
                    object=_create_workspace_resource_reference(workspace_id),
                    relation=relation,
                    subject=_create_principal_subject_reference(principal_id),
                )

                response = stub.Check(check_request)

                # Use protobuf enum for robust status checking
                if response.allowed == allowed_pb2.Allowed.ALLOWED_TRUE:
                    logger.debug(
                        f"Access granted: principal={principal_id}, workspace={workspace_id}, relation={relation}"
                    )
                    return True
                elif response.allowed == allowed_pb2.Allowed.ALLOWED_FALSE:
                    logger.debug(
                        f"Access denied: principal={principal_id}, workspace={workspace_id}, relation={relation}"
                    )
                    return False
                else:
                    # Handle unexpected allowed status values
                    logger.warning(
                        f"Unexpected allowed status from Inventory API: {response.allowed}, "
                        f"workspace={workspace_id}, principal={principal_id}, relation={relation}"
                    )
                    return False

        except Exception as e:
            logger.error(
                f"Error checking workspace access via Inventory API: {str(e)}, "
                f"workspace={workspace_id}, principal={principal_id}"
            )
            return False

    def lookup_accessible_workspaces(
        self, principal_id: str, relation: str
    ) -> Set[str]:
        """
        Lookup which workspaces are accessible to the principal using Inventory API StreamedListObjects.

        This uses the Inventory API v1beta2's StreamedListObjects method which efficiently streams all
        accessible workspaces in a single call. It answers the question:
        "Which workspaces does this principal have the specified relation to?"

        Args:
            principal_id: Principal identifier (e.g., "localhost/username")
            relation: The relation to check

        Returns:
            Set[str]: Set of workspace IDs that the principal has access to
        """
        accessible_workspaces = set()

        try:
            with create_client_channel_inventory(
                settings.INVENTORY_API_SERVER
            ) as channel:
                stub = inventory_service_pb2_grpc.KesselInventoryServiceStub(channel)

                # Build StreamedListObjects request
                request_data = (
                    streamed_list_objects_request_pb2.StreamedListObjectsRequest(
                        object_type=representation_type_pb2.RepresentationType(
                            resource_type="workspace",
                            reporter_type="rbac",
                        ),
                        relation=relation,
                        subject=_create_principal_subject_reference(principal_id),
                    )
                )

                # Stream all accessible workspace objects
                responses = stub.StreamedListObjects(request_data)

                # Iterate through all accessible resources
                for response in responses:
                    response_dict = json_format.MessageToDict(response)
                    # Extract the workspace ID from the response
                    if (
                        "object" in response_dict
                        and "resourceId" in response_dict["object"]
                    ):
                        workspace_id = response_dict["object"]["resourceId"]
                        accessible_workspaces.add(workspace_id)
                    else:
                        logger.warning(
                            f"Malformed workspace response from StreamedListObjects: "
                            f"missing object.resourceId in response for principal={principal_id}"
                        )

            logger.debug(
                f"Accessible workspaces for principal={principal_id}: "
                f"{len(accessible_workspaces)} found via StreamedListObjects"
            )

        except Exception as e:
            logger.error(
                f"Error looking up accessible workspaces via Inventory API StreamedListObjects: {str(e)}, "
                f"principal={principal_id}"
            )

        return accessible_workspaces
