"""Model for audit logging."""
from django.db import models
from api.models import User


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
    requester = models.TextField(max_length=255, null=False) # probs need a max length allowed here 
    description = models.TextField(max_length=255, null=False) # probs need a max length allowed here 
    resource = models.CharField(max_length=32, choices=RESOURCE_CHOICES)
    action = models.CharField(max_length=32, choices=ACTION_CHOICES)

    def create_data(self, request, resource, action):
        self.requester = request.user.username
        self.description = "Created " + request.data["name"]
        self.resource = resource
        self.action = action
        super(AuditLogModel, self).save()

    def delete_data(self, request, object, resource, action, *args, **kwargs):
        get_uuid = kwargs["kwargs"]["uuid"]
        if get_uuid == str(object.uuid):
            get_object_name = object.name
        else:
            raise ValueError
        self.requester = request._user.username
        self.description = "Deleted " + get_object_name
        self.resource = resource
        self.action = action 
        super(AuditLogModel, self).save()
  
    def edit_data(self, request, resource, action):
        self.requester = request.user.username
        self.description = "Edited " + request.data["name"]
        self.resource = resource
        self.action = action 
        super(AuditLogModel, self).save()

