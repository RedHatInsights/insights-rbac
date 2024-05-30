#
# Copyright 2023 Red Hat, Inc.
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
"""Model for audit logging."""
from django.db import models
from django.shortcuts import get_object_or_404
from django.utils import timezone
from management.principal.model import Principal
from api.models import Tenant, TenantAwareModel
from management.principal.model import Principal
from management.group.model import Group
from management.role.model import Role
from management.policy.model import Policy
import management.utils


class AuditLog(TenantAwareModel):
    """An audit log."""

    GROUP = "group"
    ROLE = "role"
    USER = "user"
    PERMISSION = "permission"
    RESOURCE_CHOICES = (
        (GROUP, "Group"),
        (ROLE, "Role"),
        (USER, "User"),
        (PERMISSION, "Permission"),
    )

    DELETE = "delete"
    ADD = "add"
    EDIT = "edit"
    CREATE = "create"
    REMOVE = "remove"
    ACTION_CHOICES = (
        (DELETE, "Delete"),
        (ADD, "Add"),
        (EDIT, "Edit"),
        (CREATE, "Create"),
        (REMOVE, "Remove"),
    )

    created = models.DateTimeField(default=timezone.now)
    principal = models.ForeignKey(Principal, on_delete=models.SET_NULL, null=True)
    principal_username = models.TextField(max_length=255, null=False)
    description = models.TextField(max_length=255, null=False)
    resource_type = models.CharField(max_length=32, choices=RESOURCE_CHOICES)
    resource_id = models.IntegerField(null=True)
    action = models.CharField(max_length=32, choices=ACTION_CHOICES)
    tenant = models.ForeignKey(Tenant, on_delete=models.SET_NULL, null=True)

    # helper function to find the ID of the related object
    def get_resource_item(self, r_type, request, *args, **kwargs):
        if r_type == AuditLog.ROLE:
            role_items = []
            if request.data != {}:
                role_object = get_object_or_404(Role, name=request.data["name"])
                # retrieve role id and name
                role_object_id = role_object.id
                role_object_name = "role: " + role_object.name
                role_items.append(role_object_id)
                role_items.append(role_object_name)
                return role_items
            else:
                role_object = kwargs["kwargs"]
                role_object_id = role_object.id
                role_object_name = "role: " + role_object.name
                role_items.append(role_object_id)
                role_items.append(role_object_name)
                return role_items

        elif r_type == AuditLog.GROUP:
            group_items = []
            if request._data != None:
                group_object = get_object_or_404(Group, name=request.data["name"])
                group_object_id = group_object.id 
                group_object_name = "group: " + group_object.name
                group_items.append(group_object_id)
                group_items.append(group_object_name)
                return group_items
            else:
                group_uuid = kwargs["kwargs"]["uuid"]
                group_object = get_object_or_404(Group, uuid=group_uuid)
                group_object_id = group_object.id
                group_object_name = "group: " + group_object.name
                group_items.append(group_object_id)
                group_items.append(group_object_name)
                return group_items

        elif r_type == AuditLog.PERMISSION:
            policy_items = []
            if request._data != None:
                policy_object = get_object_or_404(Policy, name=request.data["name"])
                policy_object_id = policy_object.id
                policy_object_name = "policy: " + policy_object.name
                policy_items.append(policy_object_id)
                policy_items.append(policy_object_name)
            return None
        elif r_type == "principal":
            current_user = management.utils.get_principal_from_request(request)
            principal_object = get_object_or_404(Principal, username=current_user.username)
            list_principal_object = [principal_object.id, principal_object.username]
            return list_principal_object
        elif r_type == "tenant":
            tenant_object = get_object_or_404(Tenant, org_id=request._user.org_id)
            return tenant_object.id
        else:
            return ValueError(
                "This resource type does not exist. It needs to be either: group, role, principal/user, tenant, or permission"
            )

    def log_create(self, request, resource):
        """Audit Log when group or user is created."""
        principal_items = self.get_resource_item("principal", request)
        self.principal_id = principal_items[0]
        self.principal_username = principal_items[1]

        create_resource_items = self.get_resource_item(resource, request)

        self.resource_type = resource

        self.resource_id = create_resource_items[0]
        self.description = "Created " + create_resource_items[1]

        self.action = AuditLog.CREATE
        self.tenant_id = self.get_resource_item("tenant", request)
        super(AuditLog, self).save()

    def log_delete(self, object, request, resource, *args, **kwargs):
        """Audit log when a group or user is deleted."""

        print("we have entered the log delete)")
        principal_items = self.get_resource_item("principal", request)
        self.principal_id = principal_items[0]
        self.principal_username = principal_items[1]

        delete_resource_items = self.get_resource_item(resource, request, kwargs=object)
        self.resource_type = resource
        self.resource_id = delete_resource_items[0]
        self.description = "Deleted " + delete_resource_items[1]

        self.action = AuditLog.DELETE
        self.tenant_id = self.get_resource_item("tenant", request)
        super(AuditLog, self).save()
