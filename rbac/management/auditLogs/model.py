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

    def create_role(self, context):
        self.requester = context["user"]
        self.description = "Created " + context["description"]
        self.resource = self.ROLE
        self.action = self.CREATE
        self.save()
        



