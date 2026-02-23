#
# Copyright 2026 Red Hat, Inc.
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
"""QuerySet for RoleV2 lookups."""

from django.db import models


class RoleV2QuerySet(models.QuerySet):
    """Custom QuerySet for RoleV2 with domain-aware query methods."""

    def assignable(self):
        """Filter to roles that can be assigned to bindings.

        Only custom and seeded roles can be directly assigned.
        Platform roles are internal aggregations and cannot be assigned directly.
        """
        return self.exclude(type="platform")
