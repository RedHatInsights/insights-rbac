from api.models import Tenant
from django.urls import reverse
from management.models import Permission
from rest_framework.test import APIClient


def create_role(role_name, headers, role_display="", in_access_data=None):
    """Create a role."""
    access_data = [
        {
            "permission": "app:*:*",
            "resourceDefinitions": [
                {
                    "attributeFilter": {
                        "key": "key1.id",
                        "operation": "equal",
                        "value": "value1",
                    }
                }
            ],
        },
        {"permission": "app:*:read", "resourceDefinitions": []},
    ]
    if in_access_data is not None:
        access_data = in_access_data
    else:
        tenant = Tenant._get_public_tenant()
        Permission.objects.get_or_create(permission="app:*:*", tenant=tenant)
        Permission.objects.get_or_create(permission="app:*:read", tenant=tenant)
    test_data = {
        "name": role_name,
        "display_name": role_display,
        "access": access_data,
    }

    # create a role
    client = APIClient()
    response = client.post(reverse("v1_management:role-list"), test_data, format="json", **headers)
    return response


def create_group(group_name, headers):
    """Create a group."""
    test_data = {"name": group_name, "description": "a group!"}
    url = reverse("v1_management:group-list")
    client = APIClient()
    response = client.post(url, test_data, format="json", **headers)
    return response


def add_principal_to_group(group_uuid, username, headers):
    """Add principal to existing group."""
    url = reverse("v1_management:group-principals", kwargs={"uuid": group_uuid})
    client = APIClient()
    test_data = {"principals": [{"username": username}]}
    response = client.post(url, test_data, format="json", **headers)
    return response


def add_roles_to_group(group_uuid, role_uuids, headers):
    """Add role to existing group."""
    url = reverse("v1_management:group-roles", kwargs={"uuid": group_uuid})
    client = APIClient()
    test_data = {"roles": role_uuids}
    response = client.post(url, test_data, format="json", **headers)
    return response
