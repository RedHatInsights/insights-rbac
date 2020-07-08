from django_filters import rest_framework as filters
from management.utils import validate_and_get_key

NAME_MATCH_KEY = "name_match"
VALID_NAME_MATCHES = ["partial", "exact"]


class CommonFilters(filters.FilterSet):
    def name_filter(self, queryset, field, value):
        """Filter to lookup name, partial or exact."""
        match_criteria = validate_and_get_key(self.request.query_params, NAME_MATCH_KEY, VALID_NAME_MATCHES, "partial")

        if match_criteria == "partial":
            return queryset.filter(name__icontains=value)
        elif match_criteria == "exact":
            return queryset.filter(name__iexact=value)
