from django.db import models
from api.models import Tenant
from treebeard.mp_tree import MP_Node
from uuid import uuid4

class Workspace(MP_Node):
    name = models.CharField(max_length=100)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    uuid = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
