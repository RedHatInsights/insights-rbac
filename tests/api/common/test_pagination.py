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
from django.contrib.auth.models import User
from rest_framework.test import APIRequestFactory
from rest_framework.request import Request

from api.common.pagination import PATH_INFO, StandardResultsSetPagination, V2CursorPagination, V2ResultsSetPagination


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
        self.users_list_comp = [User.objects.create(username=f"user_{i}") for i in range(100)]
        self.queryset = User.objects.all()

    def test_default_limit(self):
        """Test the default limit."""
        request = Request(self.factory.get("/foo/"))
        paginated_queryset = self.paginator.paginate_queryset(self.queryset, request)
        self.assertEqual(len(paginated_queryset), StandardResultsSetPagination.default_limit)
        self.assertEqual(self.paginator.limit, StandardResultsSetPagination.default_limit)
        self.assertEqual(self.paginator.max_limit, StandardResultsSetPagination.max_limit)

    def test_explicit_limit(self):
        """Test an explicit limit."""
        request = Request(self.factory.get("/foo/?limit=5"))
        paginated_queryset = self.paginator.paginate_queryset(self.queryset, request)
        self.assertEqual(len(paginated_queryset), 5)
        self.assertEqual(self.paginator.limit, 5)
        self.assertEqual(self.paginator.max_limit, StandardResultsSetPagination.max_limit)

    def test_no_limit(self):
        """Test no limit."""
        request = Request(self.factory.get("/foo/?limit=-1"))
        paginated_queryset = self.paginator.paginate_queryset(self.queryset, request)
        self.assertEqual(len(paginated_queryset), self.queryset.count())
        self.assertEqual(self.paginator.limit, self.queryset.count())
        self.assertEqual(self.paginator.max_limit, None)

    def test_empty_queryset(self):
        """Test empty queryset with no limit."""
        request = Request(self.factory.get("/foo/?limit=-1"))
        empty_queryset = User.objects.none()

        paginated_queryset = self.paginator.paginate_queryset(empty_queryset, request)
        self.assertEqual(len(paginated_queryset), 0)
        self.assertEqual(self.paginator.limit, 0)
        self.assertEqual(self.paginator.max_limit, None)


class V2CursorPaginationTest(TestCase):
    """Tests against the V2CursorPagination functions."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.paginator = V2CursorPagination()
        self.users_list_comp = [User.objects.create(username=f"cursor_user_{i}") for i in range(25)]
        self.queryset = User.objects.filter(username__startswith="cursor_user_").order_by("-date_joined")

    def tearDown(self):
        User.objects.filter(username__startswith="cursor_user_").delete()

    def test_default_page_size(self):
        """Test the default page size."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/"))
        paginated_queryset = self.paginator.paginate_queryset(self.queryset, request)
        self.assertEqual(len(paginated_queryset), 10)

    def test_explicit_limit(self):
        """Test an explicit limit via page_size_query_param."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?limit=5"))
        paginated_queryset = self.paginator.paginate_queryset(self.queryset, request)
        self.assertEqual(len(paginated_queryset), 5)

    def test_max_page_size(self):
        """Test that max page size is enforced."""
        self.assertEqual(self.paginator.max_page_size, 1000)

    def test_cursor_query_param(self):
        """Test that cursor query param is set correctly."""
        self.assertEqual(self.paginator.cursor_query_param, "cursor")

    def test_get_paginated_response_structure(self):
        """Test the paginated response structure."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/"))
        request.META[PATH_INFO] = "/api/rbac/v2/role-bindings/by-subject/"
        paginated_queryset = self.paginator.paginate_queryset(self.queryset, request)
        response = self.paginator.get_paginated_response([{"id": 1}])

        self.assertIn("meta", response.data)
        self.assertIn("links", response.data)
        self.assertIn("data", response.data)
        self.assertEqual(response.data["meta"]["limit"], 10)
        self.assertIn("next", response.data["links"])
        self.assertIn("previous", response.data["links"])

    def test_get_paginated_response_uses_actual_limit(self):
        """Test that paginated response uses the actual limit from request."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?limit=25"))
        request.META[PATH_INFO] = "/api/rbac/v2/role-bindings/by-subject/"
        self.paginator.paginate_queryset(self.queryset, request)
        response = self.paginator.get_paginated_response([{"id": 1}])

        self.assertEqual(response.data["meta"]["limit"], 25)

    def test_link_rewrite_with_path_info(self):
        """Test link rewrite with PATH_INFO in request META."""
        request = Mock()
        request.META = {PATH_INFO: "/api/rbac/v2/role-bindings/by-subject/"}
        link = "http://localhost:8000/api/rbac/v2/role-bindings/by-subject/?cursor=abc123"
        expected = "/api/rbac/v2/role-bindings/by-subject/?cursor=abc123"
        result = V2CursorPagination.link_rewrite(request, link)
        self.assertEqual(result, expected)

    def test_link_rewrite_without_path_info(self):
        """Test link rewrite without PATH_INFO returns original link."""
        request = Mock()
        request.META = {}
        link = "http://localhost:8000/api/rbac/v2/role-bindings/by-subject/?cursor=abc123"
        result = V2CursorPagination.link_rewrite(request, link)
        self.assertEqual(result, link)

    def test_link_rewrite_with_none_link(self):
        """Test link rewrite with None link returns None."""
        request = Mock()
        request.META = {PATH_INFO: "/api/rbac/v2/role-bindings/by-subject/"}
        result = V2CursorPagination.link_rewrite(request, None)
        self.assertIsNone(result)

    @patch("api.common.pagination.CursorPagination.get_next_link", return_value=None)
    def test_get_next_link_none(self, mock_super):
        """Test get_next_link returns None when super returns None."""
        link = self.paginator.get_next_link()
        self.assertIsNone(link)

    @patch("api.common.pagination.CursorPagination.get_previous_link", return_value=None)
    def test_get_previous_link_none(self, mock_super):
        """Test get_previous_link returns None when super returns None."""
        link = self.paginator.get_previous_link()
        self.assertIsNone(link)

    @patch("api.common.pagination.CursorPagination.get_next_link")
    def test_get_next_link_rewrites(self, mock_super):
        """Test get_next_link rewrites the link."""
        mock_super.return_value = "http://localhost:8000/api/rbac/v2/role-bindings/by-subject/?cursor=xyz"
        self.paginator.request = Mock()
        self.paginator.request.META = {PATH_INFO: "/api/rbac/v2/role-bindings/by-subject/"}
        link = self.paginator.get_next_link()
        self.assertEqual(link, "/api/rbac/v2/role-bindings/by-subject/?cursor=xyz")

    @patch("api.common.pagination.CursorPagination.get_previous_link")
    def test_get_previous_link_rewrites(self, mock_super):
        """Test get_previous_link rewrites the link."""
        mock_super.return_value = "http://localhost:8000/api/rbac/v2/role-bindings/by-subject/?cursor=abc"
        self.paginator.request = Mock()
        self.paginator.request.META = {PATH_INFO: "/api/rbac/v2/role-bindings/by-subject/"}
        link = self.paginator.get_previous_link()
        self.assertEqual(link, "/api/rbac/v2/role-bindings/by-subject/?cursor=abc")
