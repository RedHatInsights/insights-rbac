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
        (GROUP, "group"),
        (ROLE, "role"),
        (USER, "user"),
        (PERMISSION, "permission"),
    )

    DELETE = "delete"
    ADD = "add"
    EDIT = "edit" 
    CREATE = "create"
    REMOVE = "remove"
    ACTION_CHOICES = (
        (DELETE, "delete"),
        (ADD, "add"),
        (EDIT, "edit"),
        (CREATE, "create"),
        (REMOVE, "remove"),
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

    def delete_data(self, request, role, resource, action, *args, **kwargs):

        get_uuid = kwargs["kwargs"]["uuid"]
        if get_uuid == str(role.uuid):
            get_role_name = role.name
        else:
            raise ValueError
        self.requester = request._user.username
        self.description = "Deleted " + get_role_name
        self.resource = resource
        self.action = action 
        super(AuditLogModel, self).save()
  
    def edit_data(self, request, resource, action):
        self.requester = request.user.username
        self.description = "Edited " + request.data["name"]
        self.resource = resource
        self.action = action 
        super(AuditLogModel, self).save()
