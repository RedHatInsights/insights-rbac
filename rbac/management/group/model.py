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

"""Model for group management."""
import logging
from uuid import uuid4

from django.conf import settings
from django.db import models
from django.db.models import signals
from django.utils import timezone
from internal.integration import sync_handlers
from management.cache import AccessCache
from management.principal.model import Principal
from management.rbac_fields import AutoDateTimeField
from management.role.model import Role

from api.models import TenantAwareModel


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Group(TenantAwareModel):
    """A group."""

    uuid = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
    name = models.CharField(max_length=150)
    description = models.TextField(null=True)
    principals = models.ManyToManyField(Principal, related_name="group")
    created = models.DateTimeField(default=timezone.now)
    modified = AutoDateTimeField(default=timezone.now)
    platform_default = models.BooleanField(default=False)
    system = models.BooleanField(default=False)
    admin_default = models.BooleanField(default=False)

    def roles(self):
        """Roles for a group."""
        return Role.objects.filter(policies__in=self.__policy_ids()).distinct()

    def roles_with_access(self):
        """Queryset for roles with access data prefetched."""
        return self.roles().prefetch_related("access")

    def role_count(self):
        """Role count for a group."""
        return self.roles().count()

    def platform_default_set():
        """Queryset for platform default group."""
        return Group.objects.filter(platform_default=True)

    def admin_default_set():
        """Queryset for admin default group."""
        return Group.objects.filter(admin_default=True)

    def __policy_ids(self):
        """Policy IDs for a group."""
        return self.policies.values_list("id", flat=True)

    class Meta:
        ordering = ["name", "modified"]
        constraints = [models.UniqueConstraint(fields=["name", "tenant"], name="unique group name per tenant")]


def group_deleted_cache_handler(sender=None, instance=None, using=None, **kwargs):
    """Signal handler to purge principal caches when a Group is deleted."""
    logger.info("Handling signal for deleted group %s - invalidating policy cache for users in group", instance)
    if settings.AUTHENTICATE_WITH_ORG_ID:
        cache = AccessCache(instance.tenant.org_id)
    else:
        cache = AccessCache(instance.tenant.tenant_name)
    for principal in instance.principals.all():
        cache.delete_policy(principal.uuid)


def principals_to_groups_cache_handler(
    sender=None, instance=None, action=None, reverse=None, model=None, pk_set=None, using=None, **kwargs
):
    """Signal handler to purge caches when Group membership changes."""
    if settings.AUTHENTICATE_WITH_ORG_ID:
        cache = AccessCache(instance.tenant.org_id)
    else:
        cache = AccessCache(instance.tenant.tenant_name)
    if action in ("post_add", "pre_remove"):
        logger.info("Handling signal for %s group membership change - invalidating policy cache", instance)
        if isinstance(instance, Group):
            # One or more principals was added to/removed from the group
            for principal in Principal.objects.filter(pk__in=pk_set):
                cache.delete_policy(principal.uuid)
        elif isinstance(instance, Principal):
            # One or more groups was added to/removed from the principal
            cache.delete_policy(instance.uuid)
    elif action == "pre_clear":
        logger.info("Handling signal for %s group membership clearing - invalidating policy cache", instance)
        if isinstance(instance, Group):
            # All principals are being removed from this group
            for principal in instance.principals.all():
                cache.delete_policy(principal.uuid)
        elif isinstance(instance, Principal):
            # All groups are being removed from this principal
            cache.delete_policy(instance.uuid)


def group_deleted_sync_handler(sender=None, instance=None, using=None, **kwargs):
    """Signal handler to inform external services of Group deletions."""
    logger.info("Handling signal for deleted group %s - informing sync topic", instance)
    sync_handlers.send_sync_message(
        event_type="group_deleted", payload={"group": {"name": instance.name, "uuid": str(instance.uuid)}}
    )

def send_kafka():
    logger.info("send_kafka")
    sync_handlers.send_sync_message(
        event_type="group_membership_changed",
        payload={"group": {"name": "TEST"}, "action": "Test"},
    )
    logger.info("send_kafka END")

def principal_group_change_sync_handler(
    sender=None, instance=None, action=None, reverse=None, model=None, pk_set=None, using=None, **kwargs
):
    """Signal handler to inform external services of Group membership changes."""
    logger.info("Handling signal for group %s membership change - informing sync topic", instance)
    if action in ["post_add", "pre_remove", "pre_clear"]:
        logger.info("Sync group %s for %s", instance, action)
        if isinstance(instance, Group):
            logger.info("Sync group Group %s for %s", instance, action)
            sync_handlers.send_sync_message(
                event_type="group_membership_changed",
                payload={
                    "group": {"name": instance.name, "uuid": str(instance.uuid)},
                    "action": action.split("_")[-1],
                },
            )
        elif isinstance(instance, Principal):
            logger.info("Sync group Principal %s for %s", instance, action)
            groups = instance.group.all()
            for group in groups:
                sync_handlers.send_sync_message(
                    event_type="group_membership_changed",
                    payload={"group": {"name": group.name, "uuid": str(group.uuid)}, "action": action.split("_")[-1]},
                )

        logger.info("Sync group END %s for %s", instance, action)


if settings.ACCESS_CACHE_ENABLED and settings.ACCESS_CACHE_CONNECT_SIGNALS:
    signals.pre_delete.connect(group_deleted_cache_handler, sender=Group)
    signals.m2m_changed.connect(principals_to_groups_cache_handler, sender=Group.principals.through)

if settings.KAFKA_ENABLED:
    signals.pre_delete.connect(group_deleted_sync_handler, sender=Group)
    signals.m2m_changed.connect(principal_group_change_sync_handler, sender=Group.principals.through)
