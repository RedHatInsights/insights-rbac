#
# Copyright 2020 Red Hat, Inc.
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

"""Describes the urls and patterns for internal routes."""

from django.urls import path

from . import integration_views, views

integration_urlpatterns = [
    path("api/integrations/tenant/<str:org_id>/groups/", integration_views.groups, name="integration-groups"),
    path(
        "api/integrations/tenant/<str:org_id>/groups/<str:uuid>/roles/",
        integration_views.roles_for_group,
        name="integration-group-roles",
    ),
    path(
        "api/integrations/tenant/<str:org_id>/principal/<str:principals>/groups/",
        integration_views.groups_for_principal,
        name="integration-princ-groups",
    ),
    path(
        "api/integrations/tenant/<str:org_id>/principal/<str:principals>/groups/<str:uuid>/roles/",
        integration_views.roles_for_group_principal,
        name="integration-princ-roles",
    ),
]

urlpatterns = [
    path("api/tenant/unmodified/", views.list_unmodified_tenants),
    path("api/tenant/", views.list_tenants),
    path("api/tenant/<str:tenant_name>/", views.tenant_view),
    path("api/migrations/run/", views.run_migrations),
    path("api/migrations/progress/", views.migration_progress),
    path("api/seeds/run/", views.run_seeds),
    path("api/cars/expire/", views.car_expiry),
    path("api/sentry_debug/", views.trigger_error),
    path("api/utils/sync_schemas/", views.sync_schemas),
    path("api/utils/populate_tenant_account_id/", views.populate_tenant_account_id),
    path("api/utils/invalid_default_admin_groups/", views.invalid_default_admin_groups),
]

urlpatterns.extend(integration_urlpatterns)
