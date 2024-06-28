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
"""Describes the urls and patterns for the management application."""
from django.conf.urls import include
from django.urls import re_path
from management.views import (
    WorkspaceViewSet,
)
from rest_framework.routers import DefaultRouter


ROUTER = DefaultRouter()
ROUTER.register(r"workspaces", WorkspaceViewSet)

# pylint: disable=invalid-name
urlpatterns = [
    re_path(r"^", include(ROUTER.urls)),
]
