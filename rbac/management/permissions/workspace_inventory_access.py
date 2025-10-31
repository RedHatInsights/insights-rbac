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

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def _with_inventory_client(default_return):
    """
    Open inventory stub, handle connectivity and transport errors.

    This decorator handles gRPC connectivity and transport errors, returning
    a default value when the Inventory API is unreachable. It does NOT catch
    programming errors (AttributeError, TypeError, etc.) which should bubble
    up for debugging.

    Args:
        default_return: The value to return if connectivity/transport errors occur

    Returns:
        Decorator function
    """

    def decorator(fn):
        def wrapper(self, *args, **kwargs):
            try:
                with inventory_client(settings.INVENTORY_API_SERVER) as stub:
                    return fn(self, stub, *args, **kwargs)
            except (ConnectionError, TimeoutError, OSError) as e:
                # Network/connectivity errors - log and return default
                logger.error(f"Inventory API connectivity error: {type(e).__name__}: {e}")
                return default_return
            except Exception as e:
                # For gRPC errors, we should be more specific
                error_name = type(e).__name__
                if "grpc" in error_name.lower() or "rpc" in error_name.lower():
                    # gRPC transport errors - log and return default
                    logger.error(f"Inventory API gRPC error: {error_name}: {e}")
                    return default_return
                else:
                    # Programming errors - let them bubble up for debugging
                    logger.exception(f"Unexpected error in Inventory API call: {error_name}: {e}")
                    raise

        return wrapper

    return decorator


class WorkspaceInventoryAccessChecker:
    """Check workspace access using Inventory API."""

    @_with_inventory_client(default_return=False)
    def check_workspace_access(
        self,
        stub,
        workspace_id: str,
        principal_id: str,
        relation: str,
    ) -> bool:
        """
        Check if a principal has access to a specific workspace using Inventory API Check.

        Args:
            stub: The gRPC stub for making API calls
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

        response = stub.Check(check_request)

        # Use protobuf enum for robust status checking
        if response.allowed == allowed_pb2.Allowed.ALLOWED_TRUE:
            logger.debug(f"Access granted: principal={principal_id}, workspace={workspace_id}, relation={relation}")
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

    @_with_inventory_client(default_return=set())
    def lookup_accessible_workspaces(self, stub, principal_id: str, relation: str) -> Set[str]:
        """
        Lookup which workspaces are accessible to the principal using Inventory API StreamedListObjects.

        This uses the Inventory API v1beta2's StreamedListObjects method which efficiently streams all
        accessible workspaces in a single call. It answers the question:
        "Which workspaces does this principal have the specified relation to?"

        Args:
            stub: The gRPC stub for making API calls
            principal_id: Principal identifier (e.g., "localhost/username")
            relation: The relation to check

        Returns:
            Set[str]: Set of workspace IDs that the principal has access to
        """
        accessible_workspaces = set()

        # Build StreamedListObjects request
        request_data = streamed_list_objects_request_pb2.StreamedListObjectsRequest(
            object_type=representation_type_pb2.RepresentationType(
                resource_type="workspace",
                reporter_type="rbac",
            ),
            relation=relation,
            subject=make_subject_ref(principal_id),
        )

        # Stream all accessible workspace objects
        responses = stub.StreamedListObjects(request_data)

        # Iterate through all accessible resources
        for response in responses:
            # Extract the workspace ID from the response protobuf object
            if hasattr(response, "object") and hasattr(response.object, "resource_id") and response.object.resource_id:
                workspace_id = response.object.resource_id
                accessible_workspaces.add(workspace_id)
            else:
                logger.warning(
                    f"Malformed workspace response from StreamedListObjects: "
                    f"missing object.resource_id in response for principal={principal_id}"
                )

        logger.debug(
            f"Accessible workspaces for principal={principal_id}: "
            f"{len(accessible_workspaces)} found via StreamedListObjects"
        )

        return accessible_workspaces
