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


class WorkspaceInventoryAccessChecker:
    """Check workspace access using Inventory API."""

    def check_workspace_access(
        self, workspace_id: str, principal_id: str, relation: str = "inventory_host_view"
    ) -> bool:
        """
        Check if a principal has access to a specific workspace using Inventory API Check.

        Args:
            workspace_id: UUID of the workspace to check
            principal_id: Principal identifier (e.g., "localhost/username")
            relation: The relation to check (default: "inventory_host_view")

        Returns:
            bool: True if principal has access, False otherwise
        """
        try:
            with create_client_channel_inventory(settings.INVENTORY_API_SERVER) as channel:
                stub = inventory_service_pb2_grpc.KesselInventoryServiceStub(channel)

                check_request = CheckRequest(
                    object=resource_reference_pb2.ResourceReference(
                        resource_id=workspace_id,
                        resource_type="workspace",
                        reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                    ),
                    relation=relation,
                    subject=subject_reference_pb2.SubjectReference(
                        resource=resource_reference_pb2.ResourceReference(
                            resource_id=principal_id,
                            resource_type="principal",
                            reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                        )
                    ),
                )

                response = stub.Check(check_request)
                response_dict = json_format.MessageToDict(response)
                allowed = response_dict.get("allowed", "") != "ALLOWED_FALSE"

                if allowed:
                    logger.debug(
                        f"Access granted: principal={principal_id}, workspace={workspace_id}, relation={relation}"
                    )
                else:
                    logger.debug(
                        f"Access denied: principal={principal_id}, workspace={workspace_id}, relation={relation}"
                    )

                return allowed

        except Exception as e:
            logger.error(
                f"Error checking workspace access via Inventory API: {str(e)}, "
                f"workspace={workspace_id}, principal={principal_id}"
            )
            return False

    def lookup_accessible_workspaces(self, principal_id: str, relation: str = "view") -> Set[str]:
        """
        Lookup which workspaces are accessible to the principal using Inventory API StreamedListObjects.

        This uses the Inventory API v1beta2's StreamedListObjects method which efficiently streams all
        accessible workspaces in a single call. It answers the question:
        "Which workspaces does this principal have the specified relation to?"

        Args:
            principal_id: Principal identifier (e.g., "localhost/username")
            relation: The relation to check (default: "view")

        Returns:
            Set[str]: Set of workspace IDs that the principal has access to
        """
        accessible_workspaces = set()

        try:
            with create_client_channel_inventory(settings.INVENTORY_API_SERVER) as channel:
                stub = inventory_service_pb2_grpc.KesselInventoryServiceStub(channel)

                # Build StreamedListObjects request
                request_data = streamed_list_objects_request_pb2.StreamedListObjectsRequest(
                    object_type=representation_type_pb2.RepresentationType(
                        resource_type="workspace",
                        reporter_type="rbac",
                    ),
                    relation=relation,
                    subject=subject_reference_pb2.SubjectReference(
                        resource=resource_reference_pb2.ResourceReference(
                            resource_id=principal_id,
                            resource_type="principal",
                            reporter=reporter_reference_pb2.ReporterReference(type="rbac"),
                        )
                    ),
                )

                # Stream all accessible workspace objects
                responses = stub.StreamedListObjects(request_data)

                # Iterate through all accessible resources
                for response in responses:
                    response_dict = json_format.MessageToDict(response)
                    # Extract the workspace ID from the response
                    if "object" in response_dict and "resourceId" in response_dict["object"]:
                        workspace_id = response_dict["object"]["resourceId"]
                        accessible_workspaces.add(workspace_id)

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
