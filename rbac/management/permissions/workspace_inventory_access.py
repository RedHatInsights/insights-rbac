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
    request_pagination_pb2,
    streamed_list_objects_request_pb2,
)
from kessel.inventory.v1beta2.check_for_update_request_pb2 import CheckForUpdateRequest
from management.inventory_client import (
    inventory_client,
    make_resource_ref,
    make_subject_ref,
)

from rbac import settings

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class WorkspaceInventoryAccessChecker:
    """Check workspace access using Inventory API."""

    # Page size for Inventory API StreamedListObjects requests with continuation token pagination.
    PAGE_SIZE = 1000

    def _log_and_return_allowed(
        self,
        allowed_value: int,
        workspace_id: str,
        principal_id: str,
        relation: str,
    ) -> bool:
        """
        Interpret the allowed status from an Inventory API response and log the result.

        Args:
            allowed_value: The allowed enum value from the protobuf response
            workspace_id: UUID of the workspace being checked
            principal_id: Principal identifier being checked
            relation: The relation being checked

        Returns:
            bool: True if access is granted, False otherwise
        """
        if allowed_value == allowed_pb2.Allowed.ALLOWED_TRUE:
            logger.debug(
                "Access granted: principal=%s, workspace=%s, relation=%s",
                principal_id,
                workspace_id,
                relation,
            )
            return True

        if allowed_value == allowed_pb2.Allowed.ALLOWED_FALSE:
            logger.debug(
                "Access denied: principal=%s, workspace=%s, relation=%s",
                principal_id,
                workspace_id,
                relation,
            )
            return False

        # Handle unexpected allowed status values
        logger.warning(
            "Unexpected allowed status from Inventory API: %s, workspace=%s, principal=%s, relation=%s",
            allowed_pb2.Allowed.Name(allowed_value),
            workspace_id,
            principal_id,
            relation,
        )
        return False

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
        Check if a principal has access to a specific workspace using Inventory API CheckForUpdate.

        This method uses strongly consistent reads to ensure the most up-to-date permission
        state is used for all workspace access checks.

        Args:
            workspace_id: UUID of the workspace to check
            principal_id: Principal identifier (e.g., "localhost/username")
            relation: The relation to check

        Returns:
            bool: True if principal has access, False otherwise
        """
        check_request = CheckForUpdateRequest(
            object=make_resource_ref("workspace", workspace_id),
            relation=relation,
            subject=make_subject_ref(principal_id),
        )

        def rpc(stub):
            response = stub.CheckForUpdate(check_request)
            return self._log_and_return_allowed(
                response.allowed,
                workspace_id,
                principal_id,
                relation,
            )

        return self._call_inventory(rpc, False)

    def lookup_accessible_workspaces(self, principal_id: str, relation: str) -> Set[str]:
        """
        Lookup which workspaces are accessible to the principal using Inventory API StreamedListObjects.

        This uses the Inventory API v1beta2's StreamedListObjects method which efficiently streams all
        accessible workspaces using continuation token pagination. It answers the question:
        "Which workspaces does this principal have the specified relation to?"

        Args:
            principal_id: Principal identifier (e.g., "localhost/username")
            relation: The relation to check

        Returns:
            Set[str]: Set of workspace IDs that the principal has access to
        """

        def rpc(stub):
            accessible_workspaces = set()
            continuation_token = None

            while True:
                # Build pagination with continuation token if available
                pagination = request_pagination_pb2.RequestPagination(
                    limit=self.PAGE_SIZE,
                    continuation_token=continuation_token if continuation_token else "",
                )

                # Build StreamedListObjects request
                request_data = streamed_list_objects_request_pb2.StreamedListObjectsRequest(
                    object_type=representation_type_pb2.RepresentationType(
                        resource_type="workspace",
                        reporter_type="rbac",
                    ),
                    relation=relation,
                    subject=make_subject_ref(principal_id),
                    pagination=pagination,
                )

                # Stream accessible workspace objects for this page
                responses = stub.StreamedListObjects(request_data)

                # Track the last continuation token from responses
                last_token = None

                # Iterate through all accessible resources in this page
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

                    # Track continuation token from pagination info
                    if hasattr(response, "pagination") and response.pagination is not None:
                        if response.pagination.continuation_token:
                            last_token = response.pagination.continuation_token

                # Break the loop if no more pages
                if not last_token:
                    break

                # Update continuation token for next page
                continuation_token = last_token

            logger.info(
                f"Accessible workspaces for principal={principal_id}: "
                f"{len(accessible_workspaces)} found via StreamedListObjects"
            )

            return accessible_workspaces

        return self._call_inventory(rpc, set())
