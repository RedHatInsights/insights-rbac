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
from unittest.mock import Mock
from api.models import Tenant
from management.models import Permission, Role
from management.role.serializer import RoleSerializer


class RoleSerializerTest(TestCase):
    "Test the role serializer"

    def prepare_serializer(self, role_data):
        serializer = RoleSerializer(data=role_data)
        serializer.is_valid()
        tenant = Tenant.objects.get(tenant_name="public")
        request = Mock()
        request.tenant = tenant
        serializer.context["request"] = request

        return serializer

    def test_create_role_with_none_exist_permission_failed(self):
        "If the permission does not exist, error will be thrown for creating role."
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
        "If the permission does not exist, error will be thrown for updating role."
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
