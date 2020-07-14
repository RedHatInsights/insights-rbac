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

"""Filters for RBAC."""
from django_filters import rest_framework as filters
from management.utils import validate_and_get_key

NAME_MATCH_KEY = "name_match"
VALID_NAME_MATCHES = ["partial", "exact"]


class CommonFilters(filters.FilterSet):
    """Common filters."""

    def name_filter(self, queryset, field, value):
        """Filter to lookup name, partial or exact."""
        match_criteria = validate_and_get_key(self.request.query_params, NAME_MATCH_KEY, VALID_NAME_MATCHES, "partial")

        if match_criteria == "partial":
            return queryset.filter(name__icontains=value)
        elif match_criteria == "exact":
            return queryset.filter(name__iexact=value)
