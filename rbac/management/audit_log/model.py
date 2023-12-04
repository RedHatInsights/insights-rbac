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

"""Model for audit logging."""
from django.db import models


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

    date = models.DateField(auto_now_add=True)
    requester = models.TextField(max_length=255, null=False)
    description = models.TextField(max_length=255, null=False)
    resource = models.CharField(max_length=32, choices=RESOURCE_CHOICES)
    action = models.CharField(max_length=32, choices=ACTION_CHOICES)

    def log_create(self, request, resource):
        """Audit Log when group or user is created."""
        self.requester = request.user.username
        self.description = "Created " + request.data["name"]
        if resource == "role":
            self.resource = AuditLog.ROLE
        elif resource == "group":
            self.resource = AuditLog.GROUP
        self.action = AuditLog.CREATE
        super(AuditLog, self).save()

    def log_delete(self, request, object, resource, *args, **kwargs):
        """Audit log when a group or user is deleted."""
        get_uuid = kwargs["kwargs"]["uuid"]
        if get_uuid == str(object.uuid):
            get_object_name = object.name
        else:
            raise ValueError
        self.requester = request._user.username
        self.description = "Deleted " + get_object_name
        if resource == "role":
            self.resource = AuditLog.ROLE
        elif resource == "group":
            self.resource = AuditLog.GROUP
        self.action = AuditLog.DELETE
        super(AuditLog, self).save()

    def log_edit(self, request, resource):
        """Audit log when a group or user is edited."""
        self.requester = request.user.username
        self.description = "Edited " + request.data["name"]
        if resource == "role":
            self.resource = AuditLog.ROLE
        elif resource == "group":
            self.resource = AuditLog.GROUP
        self.action = AuditLog.EDIT
        super(AuditLog, self).save()
