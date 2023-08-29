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

    ADD = "add"
    DELETE = "delete"
    CREATE = "create"
    EDIT = "edit" 
    ACTION_CHOICES = (
        (ADD, "Add"),
        (DELETE, "Delete"),
        (CREATE, "Create"),
        (EDIT, "Edit"),
    )

    date = models.DateField(auto_now_add=True)
    requester = models.TextField(max_length=255, null=False) # probs need a max length allowed here 
    description = models.TextField(max_length=255, null=False) # probs need a max length allowed here 
    resource = models.CharField(max_length=32, choices=RESOURCE_CHOICES)
    action = models.CharField(max_length=32, choices=ACTION_CHOICES)

  