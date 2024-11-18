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
from internal.integration import views as integration_views
from internal.openapi import openapi

from . import views

integration_urlpatterns = [
    path(
        "api/v1/integrations/tenant/",
        integration_views.TenantViewSet.as_view({"get": "list"}),
        name="integration-tenants",
    ),
    path(
        "api/v1/integrations/tenant/<str:org_id>/roles/",
        integration_views.TenantViewSet.as_view({"get": "roles"}),
        name="integration-roles",
    ),
    path(
        "api/v1/integrations/tenant/<str:org_id>/groups/",
        integration_views.TenantViewSet.as_view({"get": "groups"}),
        name="integration-groups",
    ),
    path(
        "api/v1/integrations/tenant/<str:org_id>/groups/<str:uuid>/roles/",
        integration_views.TenantViewSet.as_view({"get": "roles_for_group"}),
        name="integration-group-roles",
    ),
    path(
        "api/v1/integrations/tenant/<str:org_id>/groups/<str:uuid>/principals/",
        integration_views.TenantViewSet.as_view({"get": "principals_for_group"}),
        name="integration-group-principals",
    ),
    path(
        "api/v1/integrations/tenant/<str:org_id>/principal/<str:principals>/groups/",
        integration_views.TenantViewSet.as_view({"get": "groups_for_principal"}),
        name="integration-princ-groups",
    ),
    path(
        "api/v1/integrations/tenant/<str:org_id>/principal/<str:principals>/groups/<str:uuid>/roles/",
        integration_views.TenantViewSet.as_view({"get": "roles_for_group_principal"}),
        name="integration-princ-roles",
    ),
    path("api/v1/openapi.json", openapi, name="openapi"),
]

urlpatterns = [
    path("api/tenant/unmodified/", views.list_unmodified_tenants),
    path("api/tenant/", views.list_tenants),
    path("api/tenant/<str:org_id>/", views.tenant_view),
    path("api/migrations/run/", views.run_migrations),
    path("api/migrations/progress/", views.migration_progress),
    path("api/seeds/run/", views.run_seeds),
    path("api/cars/expire/", views.car_expiry),
    path("api/sentry_debug/", views.trigger_error),
    path("api/utils/sync_schemas/", views.sync_schemas),
    path("api/utils/populate_tenant_account_id/", views.populate_tenant_account_id),
    path("api/utils/invalid_default_admin_groups/", views.invalid_default_admin_groups),
    path("api/utils/ocm_performance/", views.ocm_performance),
    path("api/utils/get_org_admin/<int:org_or_account>/", views.get_org_admin),
    path("api/utils/role/", views.role_removal),
    path("api/utils/permission/", views.permission_removal),
    path("api/utils/data_migration/", views.data_migration),
    path("api/utils/bindings/", views.list_bindings_for_role),
    path("api/utils/bootstrap_tenant/", views.bootstrap_tenant),
    path("api/utils/migration_resources/", views.migration_resources),
]

urlpatterns.extend(integration_urlpatterns)
