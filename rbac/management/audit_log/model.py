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
from uuid import uuid4

from django.db import models
from django.shortcuts import get_object_or_404
from django.utils import timezone
from management.group.model import Group
from management.role.model import Role

from api.models import Tenant, TenantAwareModel


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
    uuid = models.UUIDField(default=uuid4, null=False, unique=True)
    created = models.DateTimeField(default=timezone.now)
    principal_username = models.TextField(max_length=255, null=False)
    description = models.TextField(max_length=255, null=False)
    resource_type = models.CharField(max_length=32, choices=RESOURCE_CHOICES)
    resource_id = models.IntegerField(null=True)

    resource_uuid = models.UUIDField(default=uuid4)
    secondary_resource_uuid = models.UUIDField(null=True)

    action = models.CharField(max_length=32, choices=ACTION_CHOICES)
    tenant = models.ForeignKey(Tenant, on_delete=models.SET_NULL, null=True)

    def get_tenant_id(self, request):
        """Retrieve tenant id from request."""
        tenant_object = get_object_or_404(Tenant, org_id=request._user.org_id)
        return tenant_object.id

    def get_resource_item(self, r_type, request, *args, **kwargs):
        """Find related information (eg, name, id, etc...) for each resource item."""
        verify_tenant = self.get_tenant_id(request)
        if r_type == AuditLog.ROLE:
            role_object = get_object_or_404(Role, name=request.data["name"], tenant=verify_tenant)
            role_object_id = role_object.id
            role_object_uuid = role_object.uuid
            role_object_name = "role: " + role_object.name
            return role_object_id, role_object_name, role_object_uuid

        elif r_type == AuditLog.GROUP:
            group_object = get_object_or_404(Group, name=request.data["name"], tenant=verify_tenant)
            group_object_id = group_object.id
            group_object_name = "group: " + group_object.name
            group_object_uuid = group_object.uuid
            return group_object_id, group_object_name, group_object_uuid

        else:
            return ValueError("Wrong Resource Type")

    def find_edited_field(self, resource, resource_name, request, object):
        """Add additional information when group/role is edited."""
        description = resource_name + ": " + "\n "
        if request.data.get("name") != object.name:
            description = description + "Edited name \n"
        if request.data.get("description") != object.description:
            description = description + "Edited description"
        if resource == AuditLog.ROLE:
            if request.data.get("display_name") != object.display_name:
                description = description + "Edited display name \n"
            if request.data.get("access"):
                description = description + "edited access (permissions/resources)"
        return description

    def log_create(self, request, resource):
        """Audit Log when a role or a group is created."""
        self.principal_username = request.user.username

        self.resource_type = resource

        self.resource_id, resource_name, self.resource_uuid = self.get_resource_item(resource, request)
        self.description = "Created " + resource_name

        self.action = AuditLog.CREATE
        self.tenant_id = self.get_tenant_id(request)
        super(AuditLog, self).save()

    def log_delete(self, request, resource, object):
        """Audit Log when a role or a group is deleted."""
        self.principal_username = request.user.username

        self.resource_type = resource
        self.resource_id = object.id
        self.resource_uuid = object.uuid
        resource_name = self.resource_type + ": " + object.name

        self.description = "Deleted " + resource_name

        self.action = AuditLog.DELETE
        self.tenant_id = self.get_tenant_id(request)
        super(AuditLog, self).save()

    def log_edit(self, request, resource, object):
        """Audit Log when a role or a group is edit."""
        self.principal_username = request.user.username

        self.resource_type = resource
        self.resource_id = object.id
        self.resource_uuid = object.uuid
        resource_name = resource + " " + object.name

        more_information = self.find_edited_field(resource, resource_name, request, object)
        self.description = more_information
        self.action = AuditLog.EDIT
        self.tenant_id = self.get_tenant_id(request)
        super(AuditLog, self).save()

    def log_group_assignment(
        self, request, resource_type, resource, secondary_resource_object, assigned_resource_type
    ):
        """Audit Log when a role, user/principal, or service account is added to a group."""
        self.principal_username = request.user.username

        self.resource_type = resource_type
        self.resource_id = resource.id
        self.resource_uuid = resource.uuid

        resource_name = "group: " + resource.name

        if assigned_resource_type == "user":
            self.secondary_resource_uuid = secondary_resource_object.uuid
            self.description = (
                f"{assigned_resource_type} {secondary_resource_object.username} added to {resource_name}"
            )

        if assigned_resource_type == "service-account":
            self.secondary_resource_uuid = secondary_resource_object.uuid
            self.description = (
                f"{assigned_resource_type} {secondary_resource_object.username} added to {resource_name}"
            )

        if assigned_resource_type == "role":
            self.secondary_resource_uuid = secondary_resource_object["uuid"]
            self.description = f"{assigned_resource_type} {secondary_resource_object['name']} added to {resource_name}"

        self.action = AuditLog.ADD
        self.tenant_id = self.get_tenant_id(request)
        super(AuditLog, self).save()

    def log_group_remove(self, request, resource_type, resource, secondary_resource_object, assigned_resource_type):
        """Audit Log when a role, user/principal, or service account is removed from a group."""
        self.principal_username = request.user.username
        self.resource_type = resource_type
        self.resource_id = resource.id

        self.resource_uuid = resource.uuid
        resource_name = "group: " + resource.name

        if assigned_resource_type == "user":
            self.secondary_resource_uuid = secondary_resource_object.uuid
            self.description = (
                f"{assigned_resource_type} {secondary_resource_object.username} removed from {resource_name}"
            )

        if assigned_resource_type == "service-account":
            self.secondary_resource_uuid = secondary_resource_object.uuid
            self.description = (
                f"{assigned_resource_type} {secondary_resource_object.username} removed from {resource_name}"
            )

        if assigned_resource_type == "role":
            self.secondary_resource_uuid = secondary_resource_object.uuid
            self.description = (
                f"{assigned_resource_type} {secondary_resource_object.name} removed from {resource_name}"
            )

        self.action = AuditLog.REMOVE
        self.tenant_id = self.get_tenant_id(request)
        super(AuditLog, self).save()
