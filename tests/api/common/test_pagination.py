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

from rest_framework.exceptions import ValidationError

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
        # Override ordering to use a field that exists on User model
        self.paginator.ordering = "-date_joined"
        self.users_list_comp = [User.objects.create(username=f"cursor_user_{i}") for i in range(25)]
        self.queryset = User.objects.filter(username__startswith="cursor_user_")

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

    def test_empty_queryset(self):
        """Test pagination with empty queryset."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/"))
        request.META[PATH_INFO] = "/api/rbac/v2/role-bindings/by-subject/"
        empty_queryset = User.objects.none()

        paginated_queryset = self.paginator.paginate_queryset(empty_queryset, request)
        response = self.paginator.get_paginated_response([])

        self.assertEqual(len(paginated_queryset), 0)
        self.assertEqual(response.data["data"], [])
        self.assertIsNone(response.data["links"]["next"])
        self.assertIsNone(response.data["links"]["previous"])

    def test_max_page_size_enforced(self):
        """Test that requests exceeding max_page_size are capped."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?limit=2000"))
        paginated_queryset = self.paginator.paginate_queryset(self.queryset, request)

        # Should be capped to max_page_size (1000) or queryset size if smaller
        self.assertLessEqual(len(paginated_queryset), self.paginator.max_page_size)

    def test_first_page_has_no_previous(self):
        """Test that first page has no previous link."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?limit=5"))
        request.META[PATH_INFO] = "/api/rbac/v2/role-bindings/by-subject/"
        self.paginator.paginate_queryset(self.queryset, request)
        response = self.paginator.get_paginated_response([])

        self.assertIsNone(response.data["links"]["previous"])

    def test_last_page_has_no_next(self):
        """Test that last page has no next link."""
        # Request all items in one page
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?limit=100"))
        request.META[PATH_INFO] = "/api/rbac/v2/role-bindings/by-subject/"
        self.paginator.paginate_queryset(self.queryset, request)
        response = self.paginator.get_paginated_response([])

        self.assertIsNone(response.data["links"]["next"])

    def test_middle_page_has_both_links(self):
        """Test that middle pages have both next and previous links."""
        # First, get the first page to obtain cursor for next page
        request1 = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?limit=5"))
        request1.META[PATH_INFO] = "/api/rbac/v2/role-bindings/by-subject/"
        self.paginator.paginate_queryset(self.queryset, request1)
        response1 = self.paginator.get_paginated_response([])

        # Get the cursor from next link
        next_link = response1.data["links"]["next"]
        self.assertIsNotNone(next_link)

        # Extract cursor from link and make second request
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(next_link)
        cursor = parse_qs(parsed.query).get("cursor", [None])[0]
        self.assertIsNotNone(cursor)

        # Request second page
        paginator2 = V2CursorPagination()
        paginator2.ordering = "-date_joined"
        request2 = Request(self.factory.get(f"/api/rbac/v2/role-bindings/by-subject/?limit=5&cursor={cursor}"))
        request2.META[PATH_INFO] = "/api/rbac/v2/role-bindings/by-subject/"
        paginator2.paginate_queryset(self.queryset, request2)
        response2 = paginator2.get_paginated_response([])

        # Middle page should have both links
        self.assertIsNotNone(response2.data["links"]["previous"])
        self.assertIsNotNone(response2.data["links"]["next"])

    def test_cursor_navigation_returns_different_results(self):
        """Test that navigating with cursor returns different results."""
        # Get first page
        request1 = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?limit=5"))
        request1.META[PATH_INFO] = "/api/rbac/v2/role-bindings/by-subject/"
        page1 = self.paginator.paginate_queryset(self.queryset, request1)
        page1_ids = [u.id for u in page1]

        # Get cursor for next page
        response1 = self.paginator.get_paginated_response([])
        next_link = response1.data["links"]["next"]

        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(next_link)
        cursor = parse_qs(parsed.query).get("cursor", [None])[0]

        # Get second page
        paginator2 = V2CursorPagination()
        paginator2.ordering = "-date_joined"
        request2 = Request(self.factory.get(f"/api/rbac/v2/role-bindings/by-subject/?limit=5&cursor={cursor}"))
        request2.META[PATH_INFO] = "/api/rbac/v2/role-bindings/by-subject/"
        page2 = paginator2.paginate_queryset(self.queryset, request2)
        page2_ids = [u.id for u in page2]

        # Pages should have different items
        self.assertEqual(len(set(page1_ids) & set(page2_ids)), 0)

    def test_convert_order_field_rejects_simple_field(self):
        """Test _convert_order_field rejects simple field names without dot notation."""
        self.assertIsNone(self.paginator._convert_order_field("name"))
        self.assertIsNone(self.paginator._convert_order_field("modified"))
        self.assertIsNone(self.paginator._convert_order_field("uuid"))

    def test_convert_order_field_rejects_descending_simple_field(self):
        """Test _convert_order_field rejects descending simple field names."""
        self.assertIsNone(self.paginator._convert_order_field("-name"))
        self.assertIsNone(self.paginator._convert_order_field("-modified"))

    def test_convert_order_field_dot_notation_group(self):
        """Test _convert_order_field with group dot notation."""
        self.assertEqual(self.paginator._convert_order_field("group.name"), "name")
        self.assertEqual(self.paginator._convert_order_field("group.description"), "description")
        self.assertEqual(self.paginator._convert_order_field("group.user_count"), "principalCount")
        self.assertEqual(self.paginator._convert_order_field("group.uuid"), "uuid")
        self.assertEqual(self.paginator._convert_order_field("group.modified"), "modified")
        self.assertEqual(self.paginator._convert_order_field("group.created"), "created")

    def test_convert_order_field_dot_notation_group_descending(self):
        """Test _convert_order_field with group dot notation and descending prefix."""
        self.assertEqual(self.paginator._convert_order_field("-group.name"), "-name")
        self.assertEqual(self.paginator._convert_order_field("-group.user_count"), "-principalCount")

    def test_convert_order_field_dot_notation_role(self):
        """Test _convert_order_field with role dot notation."""
        self.assertEqual(self.paginator._convert_order_field("role.name"), "role_binding_entries__binding__role__name")
        self.assertEqual(self.paginator._convert_order_field("role.uuid"), "role_binding_entries__binding__role__uuid")
        self.assertEqual(
            self.paginator._convert_order_field("-role.modified"), "-role_binding_entries__binding__role__modified"
        )

    def test_convert_order_field_rejects_unknown_dot_notation(self):
        """Test _convert_order_field rejects unknown dot notation fields."""
        self.assertIsNone(self.paginator._convert_order_field("foo.bar"))
        self.assertIsNone(self.paginator._convert_order_field("-foo.bar.baz"))
        self.assertIsNone(self.paginator._convert_order_field("unknown.field"))

    def test_get_ordering_with_group_name(self):
        """Test get_ordering converts group.name to name."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?order_by=group.name"))
        ordering = self.paginator.get_ordering(request, self.queryset, None)
        self.assertEqual(ordering, ("name",))

    def test_get_ordering_with_group_name_descending(self):
        """Test get_ordering converts -group.name to -name."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?order_by=-group.name"))
        ordering = self.paginator.get_ordering(request, self.queryset, None)
        self.assertEqual(ordering, ("-name",))

    def test_get_ordering_with_group_user_count(self):
        """Test get_ordering converts group.user_count to principalCount."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?order_by=group.user_count"))
        ordering = self.paginator.get_ordering(request, self.queryset, None)
        self.assertEqual(ordering, ("principalCount",))

    def test_get_ordering_with_role_name(self):
        """Test get_ordering converts role.name to ORM path."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?order_by=role.name"))
        ordering = self.paginator.get_ordering(request, self.queryset, None)
        self.assertEqual(ordering, ("role_binding_entries__binding__role__name",))

    def test_get_ordering_with_role_name_descending(self):
        """Test get_ordering converts -role.name to descending ORM path."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?order_by=-role.name"))
        ordering = self.paginator.get_ordering(request, self.queryset, None)
        self.assertEqual(ordering, ("-role_binding_entries__binding__role__name",))

    def test_get_ordering_accepts_comma_separated_fields(self):
        """Test get_ordering accepts comma-separated fields."""
        request = Request(
            self.factory.get("/api/rbac/v2/role-bindings/by-subject/?order_by=group.name,-group.modified")
        )
        ordering = self.paginator.get_ordering(request, self.queryset, None)
        self.assertEqual(ordering, ("name", "-modified"))

    def test_get_ordering_accepts_multiple_order_by_params(self):
        """Test get_ordering accepts multiple order_by parameters."""
        request = Request(
            self.factory.get("/api/rbac/v2/role-bindings/by-subject/?order_by=group.name&order_by=-group.modified")
        )
        ordering = self.paginator.get_ordering(request, self.queryset, None)
        self.assertEqual(ordering, ("name", "-modified"))

    def test_get_ordering_rejects_direct_field_names(self):
        """Test get_ordering raises ValidationError for direct field names."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?order_by=name"))
        with self.assertRaises(ValidationError) as context:
            self.paginator.get_ordering(request, self.queryset, None)
        self.assertIn("order_by", context.exception.detail)

    def test_get_ordering_rejects_unknown_dot_notation(self):
        """Test get_ordering raises ValidationError for unknown dot notation fields."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?order_by=foo.bar"))
        with self.assertRaises(ValidationError) as context:
            self.paginator.get_ordering(request, self.queryset, None)
        self.assertIn("order_by", context.exception.detail)

    def test_get_ordering_rejects_mixed_valid_and_invalid(self):
        """Test get_ordering raises ValidationError when any field is invalid."""
        request = Request(self.factory.get("/api/rbac/v2/role-bindings/by-subject/?order_by=group.name,invalid_field"))
        with self.assertRaises(ValidationError) as context:
            self.paginator.get_ordering(request, self.queryset, None)
        self.assertIn("order_by", context.exception.detail)
