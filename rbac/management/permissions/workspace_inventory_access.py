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

import grpc
from kessel.inventory.v1beta2 import (
    allowed_pb2,
    representation_type_pb2,
    streamed_list_objects_request_pb2,
)
from kessel.inventory.v1beta2.check_request_pb2 import CheckRequest
from management.inventory_client import (
    inventory_client,
    make_resource_ref,
    make_subject_ref,
)
from rbac import settings

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class WorkspaceInventoryAccessChecker:
    """Check workspace access using Inventory API."""

    def _call_inventory(self, rpc_fn, default):
        """
        Open stub, call rpc_fn(stub), catch connectivity errors, return default on failure.

        This helper centralizes gRPC stub setup and error handling. It handles connectivity
        and transport errors by returning a default value when the Inventory API is unreachable.
        It does NOT catch programming errors (AttributeError, TypeError, etc.) which should
        bubble up for debugging.

        Args:
            rpc_fn: Function that takes a stub and performs the RPC call
            default: The value to return if connectivity/transport errors occur

        Returns:
            Result of rpc_fn(stub) or default if connectivity errors occur
        """
        try:
            with inventory_client(settings.INVENTORY_API_SERVER) as stub:
                return rpc_fn(stub)
        except (ConnectionError, TimeoutError, grpc.RpcError) as e:
            # Network/connectivity/gRPC transport errors - log and return default
            logger.error(f"Inventory API connectivity error: {type(e).__name__}: {e}")
            return default

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
        check_request = CheckRequest(
            object=make_resource_ref("workspace", workspace_id),
            relation=relation,
            subject=make_subject_ref(principal_id),
        )

        def rpc(stub):
            response = stub.Check(check_request)

            # Use protobuf enum for robust status checking
            if response.allowed == allowed_pb2.Allowed.ALLOWED_TRUE:
                logger.debug(
                    f"Access granted: principal={principal_id}, workspace={workspace_id}, relation={relation}"
                )
                return True
            elif response.allowed == allowed_pb2.Allowed.ALLOWED_FALSE:
                logger.debug(f"Access denied: principal={principal_id}, workspace={workspace_id}, relation={relation}")
                return False
            else:
                # Handle unexpected allowed status values
                logger.warning(
                    f"Unexpected allowed status from Inventory API: {response.allowed}, "
                    f"workspace={workspace_id}, principal={principal_id}, relation={relation}"
                )
                return False

        return self._call_inventory(rpc, False)

    def lookup_accessible_workspaces(self, principal_id: str, relation: str) -> Set[str]:
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
        # Build StreamedListObjects request
        request_data = streamed_list_objects_request_pb2.StreamedListObjectsRequest(
            object_type=representation_type_pb2.RepresentationType(
                resource_type="workspace",
                reporter_type="rbac",
            ),
            relation=relation,
            subject=make_subject_ref(principal_id),
        )

        def rpc(stub):
            accessible_workspaces = set()

            # Stream all accessible workspace objects
            responses = stub.StreamedListObjects(request_data)

            # Iterate through all accessible resources
            for response in responses:
                # Extract the workspace ID from the response protobuf object
                if (
                    hasattr(response, "object")
                    and hasattr(response.object, "resource_id")
                    and response.object.resource_id
                ):
                    workspace_id = response.object.resource_id
                    accessible_workspaces.add(workspace_id)
                else:
                    logger.warning(
                        f"Malformed workspace response from StreamedListObjects: "
                        f"missing object.resource_id in response for principal={principal_id}"
                    )

            logger.info(
                f"Accessible workspaces for principal={principal_id}: "
                f"{len(accessible_workspaces)} found via StreamedListObjects"
            )

            return accessible_workspaces

        return self._call_inventory(rpc, set())
