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
from uuid import uuid4

from django.conf import settings
from django.contrib.postgres.fields import JSONField
from django.db import connections, models
from django.db.models import signals
from django.utils import timezone
from management.cache import AccessCache
from management.principal.model import Principal
from management.rbac_fields import AutoDateTimeField


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Role(models.Model):
    """A role."""

    uuid = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
    name = models.CharField(max_length=150, unique=True)
    description = models.TextField(null=True)
    system = models.BooleanField(default=False)
    platform_default = models.BooleanField(default=False)
    version = models.PositiveIntegerField(default=1)
    created = models.DateTimeField(default=timezone.now)
    modified = AutoDateTimeField(default=timezone.now)

    @property
    def role(self):
        """Get role for self."""
        return self

    class Meta:
        ordering = ["name", "modified"]


class Permission(models.Model):
    """Permission for access."""

    app = models.TextField(null=False)
    resource = models.TextField(null=False)
    operation = models.TextField(null=False)
    permission = models.TextField(null=False, unique=True)

    def save(self, *args, **kwargs):
        """Populate the app, resource and operation field before saving."""
        context = self.permission.split(":")
        self.app = context[0]
        self.resource = context[1]
        self.operation = context[2]
        super(Permission, self).save(*args, **kwargs)


class Access(models.Model):
    """An access object."""

    perm = models.TextField(null=False)
    permission = models.ForeignKey(Permission, null=True, on_delete=models.CASCADE, related_name="access")
    role = models.ForeignKey(Role, null=True, on_delete=models.CASCADE, related_name="access")

    def permission_application(self):
        """Return the application name from the permission."""
        return next(iter(self.split_permission()))

    def split_permission(self):
        """Split the permission."""
        return self.perm.split(":")

    def save(self, *args, **kwargs):
        """When new Access object get created, populate the permission field."""
        # This could be removed when current Access creation logic is modified in future
        if self.perm:
            self.permission, created = Permission.objects.get_or_create(permission=self.perm)
        super(Access, self).save(*args, **kwargs)


class ResourceDefinition(models.Model):
    """A resource definition."""

    attributeFilter = JSONField(default=dict)
    access = models.ForeignKey(Access, null=True, on_delete=models.CASCADE, related_name="resourceDefinitions")

    @property
    def role(self):
        """Get role for RD."""
        if self.access:
            return self.access.role


def role_related_obj_change_cache_handler(sender=None, instance=None, using=None, **kwargs):
    """Signal handler for invalidating Principal cache on Role object change."""
    logger.info(
        "Handling signal for added/removed/changed role-related object %s - "
        "invalidating associated user cache keys",
        instance,
    )
    cache = AccessCache(connections[using].schema_name)
    if instance.role:
        for principal in Principal.objects.filter(group__policies__roles__pk=instance.role.pk):
            cache.delete_policy(principal.uuid)


if settings.ACCESS_CACHE_ENABLED:
    signals.pre_delete.connect(role_related_obj_change_cache_handler, sender=Role)
    signals.pre_delete.connect(role_related_obj_change_cache_handler, sender=Access)
    signals.pre_delete.connect(role_related_obj_change_cache_handler, sender=ResourceDefinition)
    signals.post_save.connect(role_related_obj_change_cache_handler, sender=Role)
    signals.post_save.connect(role_related_obj_change_cache_handler, sender=Access)
    signals.post_save.connect(role_related_obj_change_cache_handler, sender=ResourceDefinition)
