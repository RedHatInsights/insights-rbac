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
from typing import Optional, Set

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
    # Maximum number of pages to fetch to prevent infinite loops from buggy server responses.
    MAX_PAGES = 10000

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

    def _build_streamed_request(
        self,
        principal_id: str,
        relation: str,
        continuation_token: Optional[str],
    ) -> streamed_list_objects_request_pb2.StreamedListObjectsRequest:
        """Build a StreamedListObjects request with pagination."""
        return streamed_list_objects_request_pb2.StreamedListObjectsRequest(
            object_type=representation_type_pb2.RepresentationType(
                resource_type="workspace",
                reporter_type="rbac",
            ),
            relation=relation,
            subject=make_subject_ref(principal_id),
            pagination=request_pagination_pb2.RequestPagination(
                limit=self.PAGE_SIZE,
                continuation_token=continuation_token or "",
            ),
        )

    def _extract_workspace_id(self, response) -> Optional[str]:
        """Extract workspace ID from a StreamedListObjects response, or None if malformed."""
        obj = getattr(response, "object", None)
        if not obj:
            return None
        workspace_id = getattr(obj, "resource_id", None)
        return workspace_id or None

    def _extract_continuation_token(self, response) -> Optional[str]:
        """Extract continuation token from a response's pagination info, or None if not present."""
        pagination = getattr(response, "pagination", None)
        if not pagination:
            return None
        token = getattr(pagination, "continuation_token", None)
        return token or None

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
            page_count = 0

            while page_count < self.MAX_PAGES:
                page_count += 1

                request_data = self._build_streamed_request(principal_id, relation, continuation_token)
                responses = stub.StreamedListObjects(request_data)

                last_token = None
                for response in responses:
                    workspace_id = self._extract_workspace_id(response)
                    if workspace_id:
                        accessible_workspaces.add(workspace_id)
                    else:
                        logger.warning(
                            f"Malformed workspace response from StreamedListObjects: "
                            f"missing object.resource_id in response for principal={principal_id}"
                        )

                    token = self._extract_continuation_token(response)
                    if token:
                        last_token = token

                if not last_token:
                    break

                if last_token == continuation_token:
                    logger.warning(
                        f"Inventory API returned duplicate continuation token for principal={principal_id}. "
                        "Breaking pagination loop to avoid infinite loop."
                    )
                    break

                continuation_token = last_token

            if page_count >= self.MAX_PAGES:
                logger.warning(
                    f"Reached maximum page limit ({self.MAX_PAGES}) while fetching workspaces "
                    f"for principal={principal_id}. Some workspaces may not be included."
                )

            logger.info(
                f"Accessible workspaces for principal={principal_id}: "
                f"{len(accessible_workspaces)} found via StreamedListObjects"
            )

            return accessible_workspaces

        return self._call_inventory(rpc, set())
