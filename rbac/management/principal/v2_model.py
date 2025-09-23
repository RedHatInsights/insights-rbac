from uuid import uuid4

from django.db import models
from django.utils import timezone
from management.models import Principal, RoleBinding
from management.rbac_fields import AutoDateTimeField
from rest_framework import serializers

from api.models import TenantAwareModel


class RoleBindingPrincipal(TenantAwareModel):
    """The relationship between a RoleBinding and one of its principal subjects."""

    principal = models.ForeignKey(Principal, on_delete=models.CASCADE, related_name="role_binding_entries")
    binding = models.ForeignKey(RoleBinding, on_delete=models.CASCADE, related_name="principal_entries")
    source = models.CharField(max_length=128, default=None, null=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["principal", "binding", "source"], name="unique principal binding source triple"
            )
        ]