#
# Copyright 2019 Red Hat, Inc.
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
"""Test the API pagination module."""
from unittest.mock import Mock, patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory
from rest_framework.request import Request

from api.common.pagination import PATH_INFO, StandardResultsSetPagination, V2ResultsSetPagination


class PaginationTest(TestCase):
    """Tests against the pagination functions."""

    def test_link_rewrite(self):
        """Test the link rewrite."""
        request = Mock()
        request.META = {PATH_INFO: "/v1/providers/"}
        link = "http://localhost:8000/v1/providers/?offset=20"
        expected = "/v1/providers/?offset=20"
        result = StandardResultsSetPagination.link_rewrite(request, link)
        self.assertEqual(expected, result)

    def test_link_rewrite_rbac_prefix(self):
        """Test the link rewrite for RBAC prefix."""
        request = Mock()
        request.META = {PATH_INFO: "/api/rbac/v1/roles/"}
        link = "http://localhost:8000/api/rbac/v1/roles/?limit=10&offset=0"
        expected = "/api/rbac/v1/roles/?limit=10&offset=0"
        result = StandardResultsSetPagination.link_rewrite(request, link)
        self.assertEqual(expected, result)

    def test_link_rewrite_rbac_prefix_v2(self):
        """Test the link rewrite for RBAC prefix for v2 APIs."""
        request = Mock()
        request.META = {PATH_INFO: "/api/rbac/v2/workspaces/"}
        link = "http://localhost:8000/api/rbac/v2/workspaces/?limit=10&offset=0"
        expected = "/api/rbac/v2/workspaces/?limit=10&offset=0"
        result = StandardResultsSetPagination.link_rewrite(request, link)
        self.assertEqual(expected, result)

    def test_link_rewrite_err(self):
        """Test the link rewrite."""
        request = Mock()
        request.META = {PATH_INFO: "https://localhost:8000/providers/"}
        link = "http://localhost:8000/providers/?offset=20"
        result = StandardResultsSetPagination.link_rewrite(request, link)
        self.assertEqual(link, result)

    def test_link_no_rewrite(self):
        """Test the no link rewrite."""
        request = Mock()
        request.META = {}
        link = "http://localhost:8000/api/v1/providers/?offset=20"
        result = StandardResultsSetPagination.link_rewrite(request, link)
        self.assertEqual(link, result)

    @patch("api.common.pagination.LimitOffsetPagination.get_next_link", return_value=None)
    def test_get_next_link_none(self, mock_super):
        """Test the get next link method when super returns none."""
        paginator = StandardResultsSetPagination()
        link = paginator.get_next_link()
        self.assertIsNone(link)

    @patch("api.common.pagination.LimitOffsetPagination.get_previous_link", return_value=None)
    def test_get_previous_link_none(self, mock_super):
        """Test the get previous link method when super returns none."""
        paginator = StandardResultsSetPagination()
        link = paginator.get_previous_link()
        self.assertIsNone(link)

    @patch("api.common.pagination.LimitOffsetPagination.get_next_link")
    def test_get_next_link_value(self, mock_super):
        """Test the get next link method when super returns a value."""
        expected = "http://localhost:8000/api/v1/providers/?offset=20"
        mock_super.return_value = expected
        paginator = StandardResultsSetPagination()
        paginator.request = Mock
        paginator.request.META = {}
        link = paginator.get_next_link()
        self.assertEqual(link, expected)

    @patch("api.common.pagination.LimitOffsetPagination.get_previous_link")
    def test_get_previous_link_value(self, mock_super):
        """Test the get previous link method when super returns a value."""
        expected = "http://localhost:8000/api/v1/providers/?offset=20"
        mock_super.return_value = expected
        paginator = StandardResultsSetPagination()
        paginator.request = Mock
        paginator.request.META = {}
        link = paginator.get_previous_link()
        self.assertEqual(link, expected)


class V2ResultsSetPaginationTest(TestCase):
    """Tests against the V2ResultsSetPagination functions."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.paginator = V2ResultsSetPagination()
        self.mock_queryset = range(100)

    def test_default_limit(self):
        request = Request(self.factory.get("/foo/"))
        paginated_queryset = self.paginator.paginate_queryset(self.mock_queryset, request)
        self.assertEqual(len(paginated_queryset), StandardResultsSetPagination.default_limit)
        self.assertEqual(self.paginator.limit, StandardResultsSetPagination.default_limit)
        self.assertEqual(self.paginator.max_limit, StandardResultsSetPagination.max_limit)

    def test_explicit_limit(self):
        request = Request(self.factory.get("/foo/?limit=5"))
        paginated_queryset = self.paginator.paginate_queryset(self.mock_queryset, request)
        self.assertEqual(len(paginated_queryset), 5)
        self.assertEqual(self.paginator.limit, 5)
        self.assertEqual(self.paginator.max_limit, StandardResultsSetPagination.max_limit)

    def test_no_limit(self):
        request = Request(self.factory.get("/foo/?limit=-1"))
        all_records = self.mock_queryset
        paginated_queryset = self.paginator.paginate_queryset(all_records, request)
        self.assertEqual(len(paginated_queryset), len(all_records))
        self.assertEqual(self.paginator.limit, len(all_records))
        self.assertEqual(self.paginator.max_limit, None)
