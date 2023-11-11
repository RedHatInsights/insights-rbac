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


class AuditLogModel(models.Model):
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
    requester = models.TextField(max_length=255, null=False)  # probs need a max length allowed here
    description = models.TextField(max_length=255, null=False)  # probs need a max length allowed here
    resource = models.CharField(max_length=32, choices=RESOURCE_CHOICES)
    action = models.CharField(max_length=32, choices=ACTION_CHOICES)

    def create_data(self, request, resource):
        """Audit Log when group or user is created."""
        self.requester = request.user.username
        self.description = "Created " + request.data["name"]
        self.resource = resource
        self.action = AuditLogModel.CREATE
        super(AuditLogModel, self).save()

    def delete_data(self, request, object, resource, *args, **kwargs):
        """Audit log when a group or user is deleted."""
        get_uuid = kwargs["kwargs"]["uuid"]
        if get_uuid == str(object.uuid):
            get_object_name = object.name
        else:
            raise ValueError
        self.requester = request._user.username
        self.description = "Deleted " + get_object_name
        self.resource = resource
        self.action = AuditLogModel.DELETE
        super(AuditLogModel, self).save()

    def edit_data(self, request, resource):
        """Audit log when a group or user is edited."""
        self.requester = request.user.username
        self.description = "Edited " + request.data["name"]
        self.resource = resource
        self.action = AuditLogModel.EDIT
        super(AuditLogModel, self).save()

    def add_data(self, request, group, item, who):
        """Audit log when a role or user/principal is added to a group."""

        self.requester = request.user.username
        group_name = group.name
        
        if who == "role":
            role_name = item.display_name
            self.description = "Added role " + role_name + " to group " + group_name
            self.resource = AuditLogModel.ROLE
        elif who == "user":
            user_name = item
            self.description = "Added user " + user_name + " to group " + group_name
            self.resource = AuditLogModel.USER
        else:
            ValueError("Not role, user, or permission that is being added")

        self.action = AuditLogModel.ADD
        super(AuditLogModel, self).save()
