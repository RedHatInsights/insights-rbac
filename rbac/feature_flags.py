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
"""Feature flag module module."""
import logging
import threading
from typing import Callable, Optional

from UnleashClient import UnleashClient
from django.conf import settings

logger = logging.getLogger(__name__)


class FeatureFlags:
    """Feature flag class."""

    # Add ungrouped hosts' IDs to the returning payloads.
    TOGGLE_ADD_UNGROUPED_HOSTS_ID = "rbac.access-add-ungrouped-hosts-id.enabled"
    # Removes the null value from the list of workspace IDs.
    TOGGLE_REMOVE_NULL_VALUE = "rbac.resource-definition-remove-null-value.enabled"
    # Makes the V2 API to only allow "GET" requests.
    TOGGLE_V2_API_READONLY = "rbac.v2-api-readonly-mode.enabled"
    # Enables Inventory API access check v2 for workspace permissions.
    TOGGLE_WORKSPACE_ACCESS_CHECK_V2 = "rbac.workspace-access-check-v2.enabled"

    def __init__(self):
        """Add attributes."""
        self.client = None
        self._lock = threading.Lock()

    def initialize(self):
        """Set the client on an instance with thread safety."""
        if self.client is not None:
            return

        # Acquire a lock and double-check to avoid race conditions
        with self._lock:
            if self.client is not None:
                return

            try:
                self.client = self._init_unleash_client()
                logger.info("Feature flags client initialized successfully.")
            except Exception:
                logger.exception("Error initializing FeatureFlags client")
                self.client = None

    def _init_unleash_client(self):
        """Initialize the client."""
        client = UnleashClient(
            url=settings.FEATURE_FLAGS_URL,
            app_name=settings.APP_NAME,
            custom_headers={"Authorization": settings.FEATURE_FLAGS_TOKEN},
            cache_directory=settings.FEATURE_FLAGS_CACHE_DIR,
        )

        if settings.FEATURE_FLAGS_URL and settings.FEATURE_FLAGS_TOKEN:
            client.initialize_client()
            logger.info(f"FeatureFlags initialized using Unleash on {settings.FEATURE_FLAGS_URL}")
        else:
            logger.info(
                "FEATURE_FLAGS_URL and/or FEATURE_FLAGS_TOKEN were not set, skipping FeatureFlags initialization."
            )

        return client

    def is_enabled(
        self,
        feature_name: str,
        context: Optional[dict] = None,
        fallback_function: Optional[Callable[[str, Optional[dict]], None]] = None,
    ):
        """Override of is_enabled for checking flag values."""
        if self.client is None:
            self.initialize()

        if self.client is None:
            if fallback_function:
                logger.warning("FeatureFlags not initialized, using fallback function")
                return fallback_function(feature_name, context)
            else:
                logger.warning("FeatureFlags not initialized, defaulting to False")
                return False

        return self.client.is_enabled(feature_name, context, fallback_function=fallback_function)

    def is_add_ungrouped_hosts_id_enabled(self):
        """
        Check if "add ungrouped hosts ID" feature is enabled.

        Falls back to reading the environment variable if any error occurs.
        """
        return self.is_enabled(
            feature_name=self.TOGGLE_ADD_UNGROUPED_HOSTS_ID,
            fallback_function=lambda ignored_toggle_name, ignored_context: settings.ADD_UNGROUPED_HOSTS_ID,
        )

    def is_remove_null_value_enabled(self):
        """Check whether the "remove null value" feature is enabled.

        Falls back to reading the environment variable if any error occurs.
        """
        return self.is_enabled(
            feature_name=self.TOGGLE_REMOVE_NULL_VALUE,
            fallback_function=lambda ignored_toggle_name, ignored_context: settings.REMOVE_NULL_VALUE,
        )

    def is_v2_api_read_only_mode_enabled(self):
        """Check whether the "v2 API in readonly mode" feature is enabled.

        Falls back to reading the environment variable if any error occurs.
        """
        return self.is_enabled(
            feature_name=self.TOGGLE_V2_API_READONLY,
            fallback_function=lambda ignored_toggle_name, ignored_context: settings.V2_READ_ONLY_API_MODE,
        )

    def is_workspace_access_check_v2_enabled(self):
        """Check whether the "workspace access check v2" feature is enabled.

        Falls back to reading the environment variable if any error occurs.
        """
        return self.is_enabled(
            feature_name=self.TOGGLE_WORKSPACE_ACCESS_CHECK_V2,
            fallback_function=lambda ignored_toggle_name, ignored_context: settings.WORKSPACE_ACCESS_CHECK_V2_ENABLED,
        )


FEATURE_FLAGS = FeatureFlags()
