# Copyright 2024 Red Hat, Inc.
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
"""Top-level URL configuration for the management API.

This module serves as the entry point for all versioned management APIs.
Each version (v1, v2, etc.) has its own urls.py that aggregates resource-level routes.
"""

from django.urls import include, path

urlpatterns = [
    path("v1/", include("management.api.v1.urls")),
    path("v2/", include("management.api.v2.urls")),
]
