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

from django.db import models, connections
from django.db.models import signals
from django.utils import timezone
from management.cache import AccessCache
from management.principal.model import Principal
from management.rbac_fields import AutoDateTimeField
from management.role.model import Role


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

class Group(models.Model):
    """A group."""

    uuid = models.UUIDField(default=uuid4, editable=False,
                            unique=True, null=False)
    name = models.CharField(max_length=150, unique=True)
    description = models.TextField(null=True)
    principals = models.ManyToManyField(Principal, related_name='group')
    created = models.DateTimeField(default=timezone.now)
    modified = AutoDateTimeField(default=timezone.now)
    platform_default = models.BooleanField(default=False)
    system = models.BooleanField(default=False)

    def roles(self):
        """Roles for a group."""
        return Role.objects.filter(policies__in=self.__policy_ids()).distinct()

    def roles_with_access(self):
        """Queryset for roles with access data prefetched."""
        return self.roles().prefetch_related('access')

    def role_count(self):
        """Role count for a group."""
        return self.roles().count()

    def platform_default_set():
        """Queryset for platform default group."""
        return Group.objects.filter(platform_default=True)

    def __policy_ids(self):
        """Policy IDs for a group."""
        return self.policies.values_list('id', flat=True)

    class Meta:
        ordering = ['name', 'modified']

def group_deleted_cache_handler(sender=None, instance=None, using=None, **kwargs):
    logger.info('Handling signal for deleted group %s - invalidating policy cache for users in group', instance)
    cache = AccessCache(connections[using].schema_name)
    for principal in instance.principals.all():
        cache.delete_policy(principal.uuid)

def principals_to_groups_cache_handler(sender=None, instance=None, action=None, 
                                       reverse=None, model=None, pk_set=None, using=None,
                                       **kwargs):
    cache = AccessCache(connections[using].schema_name)
    if action in ('post_add', 'pre_remove'):
        logger.info('Handling signal for %s group membership change - invalidating policy cache', instance)
        if isinstance(instance, Group):
            # One or more principals was added to/removed from the group
            for principal in Principal.objects.filter(uuid__in=pk_set):
                cache.delete_policy(principal.uuid)
        elif isinstance(instance, Principal):
            # One or more groups was added to/removed from the principal
            cache.delete_policy(instance.uuid)
    elif action == 'pre_clear':
        logger.info('Handling signal for %s group membership clearing - invalidating policy cache', instance)
        if isinstance(instance, Group):
            # All principals are being removed from this group
            for principal in instance.principals.all():
                cache.delete_policy(principal.uuid)
        elif isinstance(instance, Principal):
            # All groups are being removed from this principal
            cache.delete_policy(instance.uuid)

            
signals.pre_delete.connect(group_deleted_cache_handler, sender=Group)
signals.m2m_changed.connect(principals_to_groups_cache_handler, 
                            sender=Group.principals.through)