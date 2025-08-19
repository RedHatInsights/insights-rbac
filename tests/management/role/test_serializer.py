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

    def setUp(self):
        self.tenant = Tenant.objects.get(tenant_name="public")
        self.root_workspace = Workspace.objects.create(
            name="Root", tenant=self.tenant, parent=None, type=Workspace.Types.ROOT
        )
        self.default_workspace = Workspace.objects.create(
            name="Default", tenant=self.tenant, parent=self.root_workspace, type=Workspace.Types.DEFAULT
        )
        self.standard_workspace = Workspace.objects.create(
            name="Standard", tenant=self.tenant, parent=self.default_workspace
        )
        self.sub_workspace_a = Workspace.objects.create(
            name="Sub a", tenant=self.tenant, parent=self.standard_workspace
        )
        self.sub_workspace_b = Workspace.objects.create(
            name="Sub b", tenant=self.tenant, parent=self.standard_workspace
        )

    def test_get_with_inventory_groups_filter_in_for_access(self):
        """Return the hierarchy locally for access."""
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
                                "value": [str(self.default_workspace.id), "foo"],
                            }
                        }
                    ],
                }
            ],
        }

        # Serialize the input
        role_serializer = RoleSerializerTest.prepare_serializer(RoleSerializerTest, role_data)
        Permission.objects.create(permission=permission_str, tenant=self.tenant)

        # Create the role
        role = role_serializer.create(role_serializer.validated_data)

        # Get the Resource Definition
        access = role.access.last()
        resource_definition = access.resourceDefinitions.last()
        resource_definition_serializer = ResourceDefinitionSerializer(
            resource_definition, context={"for_access": True}
        )
        updated_operation = resource_definition_serializer.data.get("attributeFilter").get("operation")
        actual = set(resource_definition_serializer.data.get("attributeFilter").get("value"))
        expected = {
            str(self.default_workspace.id),
            str(self.standard_workspace.id),
            str(self.sub_workspace_a.id),
            str(self.sub_workspace_b.id),
            "foo",
        }

        self.assertEqual(actual, expected)
        self.assertEqual(updated_operation, "in")

    def test_get_with_inventory_groups_filter_equal_for_access(self):
        """Return the hierarchy locally for access."""
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
                                "operation": "equal",
                                "value": str(self.default_workspace.id),
                            }
                        }
                    ],
                }
            ],
        }

        # Serialize the input
        role_serializer = RoleSerializerTest.prepare_serializer(RoleSerializerTest, role_data)
        Permission.objects.create(permission=permission_str, tenant=self.tenant)

        # Create the role
        role = role_serializer.create(role_serializer.validated_data)

        # Get the Resource Definition
        access = role.access.last()
        resource_definition = access.resourceDefinitions.last()
        resource_definition_serializer = ResourceDefinitionSerializer(
            resource_definition, context={"for_access": True}
        )
        updated_operation = resource_definition_serializer.data.get("attributeFilter").get("operation")
        actual = set(resource_definition_serializer.data.get("attributeFilter").get("value"))
        expected = {
            str(self.default_workspace.id),
            str(self.standard_workspace.id),
            str(self.sub_workspace_a.id),
            str(self.sub_workspace_b.id),
        }
        self.assertEqual(actual, expected)
        self.assertEqual(updated_operation, "in")

    def test_get_with_inventory_groups_filter_in_for_roles(self):
        """Return the hierarchy locally for roles."""
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
                                "value": [str(self.default_workspace.id), "foo"],
                            }
                        }
                    ],
                }
            ],
        }

        # Serialize the input
        role_serializer = RoleSerializerTest.prepare_serializer(RoleSerializerTest, role_data)
        Permission.objects.create(permission=permission_str, tenant=self.tenant)

        # Create the role
        role = role_serializer.create(role_serializer.validated_data)

        # Get the Resource Definition
        access = role.access.last()
        resource_definition = access.resourceDefinitions.last()
        resource_definition_serializer = ResourceDefinitionSerializer(resource_definition)
        updated_operation = resource_definition_serializer.data.get("attributeFilter").get("operation")
        actual = set(resource_definition_serializer.data.get("attributeFilter").get("value"))
        expected = {str(self.default_workspace.id), "foo"}

        self.assertEqual(actual, expected)
        self.assertEqual(updated_operation, "in")

    def test_get_with_inventory_groups_filter_equal_for_roles(self):
        """Return the hierarchy locally for roles."""
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
                                "operation": "equal",
                                "value": str(self.default_workspace.id),
                            }
                        }
                    ],
                }
            ],
        }

        # Serialize the input
        role_serializer = RoleSerializerTest.prepare_serializer(RoleSerializerTest, role_data)
        Permission.objects.create(permission=permission_str, tenant=self.tenant)

        # Create the role
        role = role_serializer.create(role_serializer.validated_data)

        # Get the Resource Definition
        access = role.access.last()
        resource_definition = access.resourceDefinitions.last()
        resource_definition_serializer = ResourceDefinitionSerializer(resource_definition)
        updated_operation = resource_definition_serializer.data.get("attributeFilter").get("operation")
        actual = resource_definition_serializer.data.get("attributeFilter").get("value")
        expected = str(self.default_workspace.id)

        self.assertEqual(actual, expected)
        self.assertEqual(updated_operation, "equal")

    def test_get_with_inventory_wildcard_filter_for_access(self):
        """Return the hierarchy locally for access with inventory:*:read permission."""
        permission_str = "inventory:*:read"
        role_data = {
            "name": "Inventory Wildcard Role",
            "access": [
                {
                    "permission": permission_str,
                    "resourceDefinitions": [
                        {
                            "attributeFilter": {
                                "key": "group.id",
                                "operation": "in",
                                "value": [str(self.default_workspace.id), "foo"],
                            }
                        }
                    ],
                }
            ],
        }

        # Serialize the input
        role_serializer = RoleSerializerTest.prepare_serializer(RoleSerializerTest, role_data)
        Permission.objects.create(permission=permission_str, tenant=self.tenant)

        # Create the role
        role = role_serializer.create(role_serializer.validated_data)

        # Get the Resource Definition
        access = role.access.last()
        resource_definition = access.resourceDefinitions.last()
        resource_definition_serializer = ResourceDefinitionSerializer(
            resource_definition, context={"for_access": True}
        )
        updated_operation = resource_definition_serializer.data.get("attributeFilter").get("operation")
        actual = set(resource_definition_serializer.data.get("attributeFilter").get("value"))
        expected = {
            str(self.default_workspace.id),
            str(self.standard_workspace.id),
            str(self.sub_workspace_a.id),
            str(self.sub_workspace_b.id),
            "foo",
        }

        self.assertEqual(actual, expected)
        self.assertEqual(updated_operation, "in")

    def test_get_with_inventory_wildcard_all_filter_for_access(self):
        """Return the hierarchy locally for access with inventory:*:* permission."""
        permission_str = "inventory:*:*"
        role_data = {
            "name": "Inventory Wildcard All Role",
            "access": [
                {
                    "permission": permission_str,
                    "resourceDefinitions": [
                        {
                            "attributeFilter": {
                                "key": "group.id",
                                "operation": "equal",
                                "value": str(self.default_workspace.id),
                            }
                        }
                    ],
                }
            ],
        }

        # Serialize the input
        role_serializer = RoleSerializerTest.prepare_serializer(RoleSerializerTest, role_data)
        Permission.objects.create(permission=permission_str, tenant=self.tenant)

        # Create the role
        role = role_serializer.create(role_serializer.validated_data)

        # Get the Resource Definition
        access = role.access.last()
        resource_definition = access.resourceDefinitions.last()
        resource_definition_serializer = ResourceDefinitionSerializer(
            resource_definition, context={"for_access": True}
        )
        updated_operation = resource_definition_serializer.data.get("attributeFilter").get("operation")
        actual = set(resource_definition_serializer.data.get("attributeFilter").get("value"))
        expected = {
            str(self.default_workspace.id),
            str(self.standard_workspace.id),
            str(self.sub_workspace_a.id),
            str(self.sub_workspace_b.id),
        }

        self.assertEqual(actual, expected)
        self.assertEqual(updated_operation, "in")

    @override_settings(WORKSPACE_RESOURCE_TYPE=["groups"])
    def test_workspace_hierarchy_with_single_resource_type(self):
        """Test that workspace hierarchy works with single resource type in list."""
        permission_str = "inventory:groups:read"
        role_data = {
            "name": "Inventory Groups Role",
            "access": [
                {
                    "permission": permission_str,
                    "resourceDefinitions": [
                        {
                            "attributeFilter": {
                                "key": "group.id",
                                "operation": "equal",
                                "value": str(self.default_workspace.id),
                            }
                        }
                    ],
                }
            ],
        }

        # Serialize the input
        role_serializer = RoleSerializerTest.prepare_serializer(RoleSerializerTest, role_data)
        Permission.objects.create(permission=permission_str, tenant=self.tenant)

        # Create the role
        role = role_serializer.create(role_serializer.validated_data)

        # Get the Resource Definition
        access = role.access.last()
        resource_definition = access.resourceDefinitions.last()
        resource_definition_serializer = ResourceDefinitionSerializer(
            resource_definition, context={"for_access": True}
        )

        # Should trigger hierarchy since "groups" is in the configured resource types
        updated_operation = resource_definition_serializer.data.get("attributeFilter").get("operation")
        actual = set(resource_definition_serializer.data.get("attributeFilter").get("value"))
        expected = {
            str(self.default_workspace.id),
            str(self.standard_workspace.id),
            str(self.sub_workspace_a.id),
            str(self.sub_workspace_b.id),
        }

        self.assertEqual(actual, expected)
        self.assertEqual(updated_operation, "in")

    @override_settings(WORKSPACE_RESOURCE_TYPE=["hosts"])
    def test_workspace_hierarchy_with_custom_resource_types(self):
        """Test that workspace hierarchy respects custom WORKSPACE_RESOURCE_TYPE setting."""
        permission_str = "inventory:hosts:read"
        role_data = {
            "name": "Inventory Hosts Role",
            "access": [
                {
                    "permission": permission_str,
                    "resourceDefinitions": [
                        {
                            "attributeFilter": {
                                "key": "group.id",
                                "operation": "equal",
                                "value": str(self.default_workspace.id),
                            }
                        }
                    ],
                }
            ],
        }

        # Serialize the input
        role_serializer = RoleSerializerTest.prepare_serializer(RoleSerializerTest, role_data)
        Permission.objects.create(permission=permission_str, tenant=self.tenant)

        # Create the role
        role = role_serializer.create(role_serializer.validated_data)

        # Get the Resource Definition
        access = role.access.last()
        resource_definition = access.resourceDefinitions.last()
        resource_definition_serializer = ResourceDefinitionSerializer(
            resource_definition, context={"for_access": True}
        )

        # Should trigger hierarchy since "hosts" is in the configured resource types
        updated_operation = resource_definition_serializer.data.get("attributeFilter").get("operation")
        actual = set(resource_definition_serializer.data.get("attributeFilter").get("value"))
        expected = {
            str(self.default_workspace.id),
            str(self.standard_workspace.id),
            str(self.sub_workspace_a.id),
            str(self.sub_workspace_b.id),
        }

        self.assertEqual(actual, expected)
        self.assertEqual(updated_operation, "in")

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
        Permission.objects.create(permission=permission_str, tenant=self.tenant)

        # Create the role
        role = role_serializer.create(role_serializer.validated_data)

        # Get the Resource Definition
        access = role.access.last()
        resource_definition = access.resourceDefinitions.last()
        resource_definition_serializer = ResourceDefinitionSerializer(resource_definition)
        actual = set(resource_definition_serializer.data.get("attributeFilter").get("value"))
        expected = {resource_value}
        self.assertEqual(actual, expected)
