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
from django.utils import timezone


class AuditLog(models.Model):
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

    created_at = models.DateTimeField(default=timezone.now)
    requester = models.TextField(max_length=255, null=False)
    description = models.TextField(max_length=255, null=False)
    resource = models.CharField(max_length=32, choices=RESOURCE_CHOICES)
    action = models.CharField(max_length=32, choices=ACTION_CHOICES)

    def log_create(self, request, resource):
        """Audit Log when group or user is created."""
        self.requester = request.user.username
        self.description = "Created " + request.data["name"]
        self.resource = resource
        self.action = AuditLog.CREATE
        super(AuditLog, self).save()

    def log_delete(self, request, object, resource, *args, **kwargs):
        """Audit log when a group or user is deleted."""
        get_uuid = kwargs["kwargs"]["uuid"]
        if get_uuid == str(object.uuid):
            get_object_name = object.name
        else:
            raise ValueError("Object name is not available/wrong.")
        self.requester = request._user.username
        self.description = "Deleted " + get_object_name
        self.resource = resource
        self.action = AuditLog.DELETE
        super(AuditLog, self).save()

    def log_edit(self, request, resource):
        """Audit log when a group or user is edited."""
        self.requester = request.user.username
        if resource == AuditLog.GROUP:
            if "description" not in request.data:
                self.description = "Edited group name to " + request.data["name"]
            else:
                self.description = (
                    "Edited group name to "
                    + request.data["name"]
                    + " and group description to "
                    + request.data["description"]
                )
        if resource == AuditLog.ROLE:
            if "description" not in request.data and "name" in request.data:
                self.description = "Edited role name to " + request.data["name"]
            elif "display_name" in request.data:
                self.description = (
                    "Edited role name to "
                    + request.data["name"]
                    + " and role display_name to "
                    + request.data["display_name"]
                )
            else:
                self.description = (
                    "Edited role name to "
                    + request.data["name"]
                    + " and role description to "
                    + request.data["description"]
                )
        self.resource = resource
        self.action = AuditLog.EDIT
        super(AuditLog, self).save()
