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

from UnleashClient import UnleashClient
from UnleashClient.cache import FileCache
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class FeatureFlags:
    """Feature flag class."""

    def __init__(self):
        """Add attributes."""
        self.client = None

    def initialize(self):
        """Set the client on an instance."""
        try:
            self.client = self._init_unleash_client()
        except Exception:
            logger.exception("Error initilizing FeatureFlags client")

    def _init_unleash_client(self):
        """Initialize the client."""
        cache = FileCache(settings.APP_NAME, directory=settings.FEATURE_FLAGS_CACHE_DIR)
        client = UnleashClient(
            url=settings.FEATURE_FLAGS_URL,
            app_name=settings.APP_NAME,
            cache=cache,
            custom_headers={"Authorization": settings.FEATURE_FLAGS_TOKEN},
        )

        if settings.FEATURE_FLAGS_URL and settings.FEATURE_FLAGS_TOKEN:
            client.initialize_client()
            logger.info(f"FeatureFlags initialized using Unleash on {settings.FEATURE_FLAGS_URL}")
        else:
            logger.info(
                "FEATURE_FLAGS_URL and/or FEATURE_FLAGS_TOKEN were not set, skipping FeatureFlags initialization."
            )

        return client

    def is_enabled(self, feature_name, context=None, fallback_function=None):
        """Override of is_enabled for checking flag values."""
        if not self.client:
            if fallback_function:
                logger.warning("FeatureFlags not initialized, using fallback function")
                return fallback_function(feature_name, context)
            else:
                logger.warning("FeatureFlags not initialized, defaulting to False")
                return False

        return self.client.is_enabled(feature_name, context, fallback_function=fallback_function)


FEATURE_FLAGS = FeatureFlags()
