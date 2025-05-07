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
from django.test import TestCase
from django.test.utils import override_settings
from unittest.mock import Mock
from api.models import Tenant
from management.models import Permission, Workspace
from management.role.serializer import RoleSerializer, ResourceDefinitionSerializer

import random


class RoleSerializerTest(TestCase):
    """Test the role serializer"""

    def prepare_serializer(self, role_data):
        serializer = RoleSerializer(data=role_data)
        serializer.is_valid()
        tenant = Tenant.objects.get(tenant_name="public")
        request = Mock()
        request.tenant = tenant
        serializer.context["request"] = request

        return serializer

    def test_create_role_with_none_exist_permission_failed(self):
        """If the permission does not exist, error will be thrown for creating role."""
        # Prepare dict input
        role_data = {
            "name": "RoleA",
            "access": [
                {
                    "permission": "app:*:write",
                    "resourceDefinitions": [
                        {"attributeFilter": {"key": "app.attribute.case", "operation": "equal", "value": "thevalue"}}
                    ],
                }
            ],
        }

        # Serialize the input
        serializer = self.prepare_serializer(role_data)

        # Create the role
        self.assertRaises(Permission.DoesNotExist, serializer.create, serializer.validated_data)

    def test_update_role_with_none_exist_permission_failed(self):
        """If the permission does not exist, error will be thrown for updating role."""
        # Prepare dict input
        role_data = {
            "name": "RoleA",
            "access": [
                {
                    "permission": "app:*:read",
                    "resourceDefinitions": [
                        {"attributeFilter": {"key": "app.attribute.case", "operation": "equal", "value": "thevalue"}}
                    ],
                }
            ],
        }

        # Serialize the input
        serializer = self.prepare_serializer(role_data)
        Permission.objects.create(permission="app:*:read", tenant=Tenant.objects.get(tenant_name="public"))

        # Create the role
        role = serializer.create(serializer.validated_data)

        # Update the role with non exist permission
        role_data["access"][0]["permission"] = "app:*:write"
        serializer = self.prepare_serializer(role_data)
        # Update the role
        self.assertRaises(Permission.DoesNotExist, serializer.update, role, serializer.validated_data)


@override_settings(WORKSPACE_HIERARCHY_ENABLED=True)
class ResourceDefinitionTest(TestCase):
    """Test the resource definition serializer"""

    def test_get_with_inventory_groups_filter(self):
        """Return the hierarchy locally."""

        tenant = Tenant.objects.create(tenant_name="Test")
        root_workspace = Workspace.objects.create(name="Root", tenant=tenant, parent=None, type=Workspace.Types.ROOT)
        default_workspace = Workspace.objects.create(
            name="Default", tenant=tenant, parent=root_workspace, type=Workspace.Types.DEFAULT
        )
        standard_workspace = Workspace.objects.create(name="Standard", tenant=tenant, parent=default_workspace)
        sub_workspace_a = Workspace.objects.create(name="Sub a", tenant=tenant, parent=standard_workspace)
        sub_workspace_b = Workspace.objects.create(name="Sub b", tenant=tenant, parent=standard_workspace)
        permission_str = "inventory:groups:read"
        role_data = {
            "name": "Inventory Group Role",
            "access": [
                {
                    "permission": permission_str,
                    "resourceDefinitions": [
                        {
                            "attributeFilter": {
                                "key": "group.id",
                                "operation": "in",
                                "value": [str(default_workspace.id)],
                            }
                        }
                    ],
                }
            ],
        }

        # Serialize the input
        role_serializer = RoleSerializerTest.prepare_serializer(RoleSerializerTest, role_data)
        Permission.objects.create(permission=permission_str, tenant=Tenant.objects.get(tenant_name="public"))

        # Create the role
        role = role_serializer.create(role_serializer.validated_data)

        # Get the Resource Definition
        access = role.access.last()
        resource_definition = access.resourceDefinitions.last()
        resource_definition_serializer = ResourceDefinitionSerializer(resource_definition)
        actual = set(resource_definition_serializer.data.get("attributeFilter").get("value"))
        expected = set(
            [str(default_workspace.id), str(standard_workspace.id), str(sub_workspace_a.id), str(sub_workspace_b.id)]
        )
        self.assertEqual(actual, expected)

    def test_get_with_other_filter(self):
        """Return correct filter values."""

        resource_value = str(random.randint(1, 1000))
        permission_str = "foo:bar:baz"
        role_data = {
            "name": "Inventory Group Role",
            "access": [
                {
                    "permission": permission_str,
                    "resourceDefinitions": [
                        {"attributeFilter": {"key": "group.id", "operation": "in", "value": [resource_value]}}
                    ],
                }
            ],
        }

        # Serialize the input
        role_serializer = RoleSerializerTest.prepare_serializer(RoleSerializerTest, role_data)
        Permission.objects.create(permission=permission_str, tenant=Tenant.objects.get(tenant_name="public"))

        # Create the role
        role = role_serializer.create(role_serializer.validated_data)

        # Get the Resource Definition
        access = role.access.last()
        resource_definition = access.resourceDefinitions.last()
        resource_definition_serializer = ResourceDefinitionSerializer(resource_definition)
        actual = set(resource_definition_serializer.data.get("attributeFilter").get("value"))
        expected = set([resource_value])
        self.assertEqual(actual, expected)
