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
from datetime import datetime
from urllib.parse import urlparse, urlencode

from rest_framework.pagination import CursorPagination
from rest_framework.response import Response

logger = logging.getLogger(__name__)


class RoleBindingCursorPagination(CursorPagination):
    """Cursor-based pagination for role bindings.

    This pagination class supports both querysets and lists.
    For lists (e.g., grouped data), it falls back to offset-based pagination
    while maintaining the cursor pagination interface.
    """

    page_size = 10
    page_size_query_param = "limit"
    max_page_size = 1000
    cursor_query_param = "cursor"
    ordering = "-modified"  # Default ordering by modification date

    def paginate_queryset(self, queryset, request, view=None):
        """Paginate the queryset or list."""
        if isinstance(queryset, list):
            return self._paginate_list(queryset, request, view)

        return super().paginate_queryset(queryset, request, view)

    def _paginate_list(self, data_list, request, view=None):
        """Handle pagination for lists (e.g., grouped data)."""
        self.request = request
        self.page_size = self.get_page_size(request)
        if not self.page_size:
            return None

        try:
            self.offset = int(request.query_params.get('offset', 0))
        except (ValueError, TypeError):
            self.offset = 0

        self.count = len(data_list)
        self.page_data = data_list[self.offset:self.offset + self.page_size]

        return self.page_data

    def get_next_link(self):
        """Create next link."""
        # Handle list pagination
        if hasattr(self, 'offset'):
            if self.offset + self.page_size >= self.count:
                return None

            # Build next link with offset, preserving other query params
            params = self.request.query_params.copy()
            params['offset'] = self.offset + self.page_size
            params['limit'] = self.page_size

            url = self.request.path
            query_string = urlencode(params)
            link = f"{url}?{query_string}"
            return self.link_rewrite(self.request, link)

        # Standard cursor pagination
        next_link = super().get_next_link()
        return self.link_rewrite(self.request, next_link)

    def get_previous_link(self):
        """Create previous link."""
        # Handle list pagination
        if hasattr(self, 'offset'):
            if self.offset <= 0:
                return None

            # Build previous link with offset, preserving other query params
            params = self.request.query_params.copy()
            offset = max(0, self.offset - self.page_size)
            params['offset'] = offset
            params['limit'] = self.page_size

            url = self.request.path
            query_string = urlencode(params)
            link = f"{url}?{query_string}"
            return self.link_rewrite(self.request, link)

        # Standard cursor pagination
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
        meta = {"limit": self.page_size}

        # Add count for list pagination
        if hasattr(self, 'count'):
            meta["count"] = self.count

        return Response(
            {
                "meta": meta,
                "links": {
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                },
                "data": data,
            }
        )
