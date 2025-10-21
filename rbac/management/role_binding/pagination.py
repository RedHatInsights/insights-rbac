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
"""Cursor-based pagination for role bindings."""
import logging
from urllib.parse import urlparse

from rest_framework.pagination import CursorPagination
from rest_framework.response import Response

logger = logging.getLogger(__name__)


class RoleBindingCursorPagination(CursorPagination):
    """Cursor-based pagination for role bindings."""

    page_size = 10
    page_size_query_param = "limit"
    max_page_size = 1000
    cursor_query_param = "cursor"
    ordering = "-latest_modified"  # Default ordering by latest modification date

    def get_next_link(self):
        """Create next link with partial URL rewrite."""
        next_link = super().get_next_link()
        return self.link_rewrite(self.request, next_link)

    def get_previous_link(self):
        """Create previous link with partial URL rewrite."""
        previous_link = super().get_previous_link()
        return self.link_rewrite(self.request, previous_link)

    @staticmethod
    def link_rewrite(request, link):
        """Rewrite the link to provide partial url."""
        if link is None:
            return link
        url = link
        if "PATH_INFO" in request.META:
            url_components = urlparse(link)
            path_and_query = url_components.path + (f"?{url_components.query}" if url_components.query else "")
            url = path_and_query
        return url

    def get_paginated_response(self, data):
        """Override pagination output to match OpenAPI spec."""
        return Response(
            {
                "meta": {"limit": self.page_size},
                "links": {
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                },
                "data": data,
            }
        )
