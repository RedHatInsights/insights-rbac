# Copyright 2019 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""URL configuration for the V1 management API.

This module aggregates all V1 resource-level URL configurations.
Each resource (role, group, etc.) defines its own urls.py with its routes.
"""

from django.urls import include, path

urlpatterns = [
    path("", include("management.api.v1.role.urls")),
    path("", include("management.api.v1.group.urls")),
    path("", include("management.api.v1.permission.urls")),
    path("", include("management.api.v1.audit_log.urls")),
    path("", include("management.api.v1.principal.urls")),
    path("", include("management.api.v1.access.urls")),
]
