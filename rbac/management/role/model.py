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

"""Model for role management."""
import logging
from typing import Union
from uuid import uuid4

from django.conf import settings
from django.db import models
from django.db.models import signals
from django.utils import timezone
from internal.integration import sync_handlers
from kessel.relations.v1beta1.common_pb2 import Relationship
from management.cache import AccessCache
from management.models import Permission, Principal
from management.rbac_fields import AutoDateTimeField
from migration_tool.models import (
    V2boundresource,
    V2role,
    V2rolebinding,
    role_binding_group_subject_tuple,
    role_binding_user_subject_tuple,
)

from api.models import TenantAwareModel


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Role(TenantAwareModel):
    """A role."""

    uuid = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
    name = models.CharField(max_length=150)
    display_name = models.CharField(default="", max_length=150)
    description = models.TextField(null=True)
    system = models.BooleanField(default=False)
    platform_default = models.BooleanField(default=False)
    version = models.PositiveIntegerField(default=1)
    created = models.DateTimeField(default=timezone.now)
    modified = AutoDateTimeField(default=timezone.now)
    admin_default = models.BooleanField(default=False)

    @property
    def role(self):
        """Get role for self."""
        return self

    class Meta:
        ordering = ["name", "modified"]
        constraints = [
            models.UniqueConstraint(fields=["name", "tenant"], name="unique role name per tenant"),
            models.UniqueConstraint(fields=["display_name", "tenant"], name="unique role display name per tenant"),
        ]

    def save(self, *args, **kwargs):
        """Ensure that display_name is populated on save."""
        if not self.display_name:
            self.display_name = self.name
        super(Role, self).save(*args, **kwargs)

    def external_role_id(self):
        """Return external role id."""
        return self.ext_relation.ext_id if hasattr(self, "ext_relation") else None

    def external_tenant_name(self):
        """Return external tenant name."""
        return self.ext_relation.ext_tenant.name if hasattr(self, "ext_relation") else None


class Access(TenantAwareModel):
    """An access object."""

    permission = models.ForeignKey(Permission, null=True, on_delete=models.CASCADE, related_name="accesses")
    role = models.ForeignKey(Role, null=True, on_delete=models.CASCADE, related_name="access")

    def permission_application(self):
        """Return the application name from the permission."""
        return self.permission.application


class ResourceDefinition(TenantAwareModel):
    """A resource definition."""

    attributeFilter = models.JSONField(default=dict)
    access = models.ForeignKey(Access, null=True, on_delete=models.CASCADE, related_name="resourceDefinitions")

    @property
    def role(self):
        """Get role for RD."""
        if self.access:
            return self.access.role


class ExtTenant(models.Model):
    """External tenant."""

    name = models.CharField(max_length=20, null=False, unique=True)


class ExtRoleRelation(models.Model):
    """External relation info of role."""

    ext_tenant = models.ForeignKey(ExtTenant, null=True, on_delete=models.CASCADE, related_name="ext_role_relation")
    ext_id = models.CharField(max_length=20, null=False)
    role = models.OneToOneField(Role, on_delete=models.CASCADE, null=False, related_name="ext_relation")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["ext_tenant", "ext_id"], name="unique external id per external tenant")
        ]


class BindingMapping(models.Model):
    """V2 binding Mapping definition."""

    # JSON encoding of migration_tool.models.V2rolebinding
    mappings = models.JSONField(default=dict)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="binding_mappings")
    resource_type_namespace = models.CharField(max_length=256, null=False)
    resource_type_name = models.CharField(max_length=256, null=False)
    resource_id = models.CharField(max_length=256, null=False)

    @classmethod
    def for_role_binding(cls, role_binding: V2rolebinding, v1_role: Union[Role, str]):
        """Create a new BindingMapping for a V2rolebinding."""
        mappings = role_binding.as_minimal_dict()
        resource = role_binding.resource
        resource_type_namespace = resource.resource_type[0]
        resource_type_name = resource.resource_type[1]
        resource_id = resource.resource_id
        role_arg: dict[str, Union[Role, str]] = (
            {"role": v1_role} if isinstance(v1_role, Role) else {"role_id": v1_role}
        )
        return cls(
            mappings=mappings,
            **role_arg,
            resource_type_namespace=resource_type_namespace,
            resource_type_name=resource_type_name,
            resource_id=resource_id,
        )

    def as_tuples(self) -> list[Relationship]:
        """Create tuples from BindingMapping model."""
        v2_role_binding = self.get_role_binding()
        return v2_role_binding.as_tuples()

    def is_unassigned(self):
        """Return true if mapping is not assigned to any groups or users."""
        return len(self.mappings.get("groups", [])) == 0 and len(self.mappings.get("users", [])) == 0

    def remove_group_from_bindings(self, group_uuid: str) -> Relationship:
        """Remove group from mappings."""
        self.mappings["groups"] = [group for group in self.mappings["groups"] if group != group_uuid]
        return role_binding_group_subject_tuple(self.mappings["id"], group_uuid)

    def add_group_to_bindings(self, group_uuid: str) -> Relationship:
        """Add group to mappings."""
        self.mappings["groups"].append(group_uuid)
        return role_binding_group_subject_tuple(self.mappings["id"], group_uuid)

    def remove_user_from_bindings(self, user_id: str) -> Relationship:
        """Remove user from mappings."""
        self.mappings["users"] = [user for user in self.mappings.get("users", []) if user != user_id]
        return role_binding_user_subject_tuple(self.mappings["id"], user_id)

    def add_user_to_bindings(self, user_id: str) -> Relationship:
        """Add user to mappings."""
        if "users" not in self.mappings:
            self.mappings["users"] = []
        if user_id not in self.mappings["users"]:
            self.mappings["users"].append(user_id)
        return role_binding_user_subject_tuple(self.mappings["id"], user_id)

    def update_mappings_from_role_binding(self, role_binding: V2rolebinding):
        """Set mappings."""
        # Validate resource and v1 role match
        resource = role_binding.resource
        if (
            resource.resource_type[0] != self.resource_type_namespace
            or resource.resource_type[1] != self.resource_type_name
            or resource.resource_id != self.resource_id
        ):
            raise Exception(
                "Resource mismatch."
                f"Expected: {self.resource_type_namespace}:{self.resource_type_name}:{self.resource_id} "
                f"but got: {resource.resource_type[0]}:{resource.resource_type[1]}:{resource.resource_id} "
            )

        self.mappings = role_binding.as_minimal_dict()

    def get_role_binding(self) -> V2rolebinding:
        """Get role binding."""
        args = {**self.mappings}
        args["resource"] = V2boundresource(
            resource_type=(self.resource_type_namespace, self.resource_type_name), resource_id=self.resource_id
        )
        args["role"] = V2role(
            id=args["role"]["id"],
            is_system=args["role"]["is_system"],
            permissions=frozenset(args["role"]["permissions"]),
        )
        args["groups"] = frozenset(args["groups"])
        args["users"] = frozenset(args["users"])
        return V2rolebinding(**args)


def role_related_obj_change_cache_handler(sender=None, instance=None, using=None, **kwargs):
    """Signal handler for invalidating Principal cache on Role object change."""
    logger.info(
        "Handling signal for added/removed/changed role-related object %s - "
        "invalidating associated user cache keys",
        instance,
    )
    cache = AccessCache(instance.tenant.org_id)
    if instance.role:
        for principal in Principal.objects.filter(group__policies__roles__pk=instance.role.pk):
            cache.delete_policy(principal.uuid)


def role_related_obj_change_sync_handler(sender=None, instance=None, using=None, **kwargs):
    """Signal handler for informing external sync of Role object changes."""
    logger.info(
        "Handling signal for added/removed/changed role-related object %s - " "informing sync topic",
        instance,
    )
    if instance.role:
        sync_handlers.send_sync_message(
            event_type="role_modified", payload={"role": {"name": instance.role.name, "uuid": str(instance.role.uuid)}}
        )


if settings.ACCESS_CACHE_ENABLED and settings.ACCESS_CACHE_CONNECT_SIGNALS:
    signals.pre_delete.connect(role_related_obj_change_cache_handler, sender=Role)
    signals.pre_delete.connect(role_related_obj_change_cache_handler, sender=Access)
    signals.pre_delete.connect(role_related_obj_change_cache_handler, sender=ResourceDefinition)
    signals.post_save.connect(role_related_obj_change_cache_handler, sender=Role)
    signals.post_save.connect(role_related_obj_change_cache_handler, sender=Access)
    signals.post_save.connect(role_related_obj_change_cache_handler, sender=ResourceDefinition)

if settings.KAFKA_ENABLED:
    signals.pre_delete.connect(role_related_obj_change_sync_handler, sender=Role)
    signals.pre_delete.connect(role_related_obj_change_sync_handler, sender=Access)
    signals.pre_delete.connect(role_related_obj_change_sync_handler, sender=ResourceDefinition)
    signals.post_save.connect(role_related_obj_change_sync_handler, sender=Role)
    signals.post_save.connect(role_related_obj_change_sync_handler, sender=Access)
    signals.post_save.connect(role_related_obj_change_sync_handler, sender=ResourceDefinition)
