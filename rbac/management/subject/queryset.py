#
# Copyright 2026 Red Hat, Inc.
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
"""QuerySet for Subject lookups."""

from typing import TYPE_CHECKING

from django.db.models import Count, Q
from management.exceptions import NotFoundError, RequiredFieldError
from management.group.model import Group
from management.principal.model import Principal

from api.models import Tenant

if TYPE_CHECKING:
    from management.subject.model import Subject


class SubjectQuerySet:
    """QuerySet-like class for Subject lookups.

    Follows Django's QuerySet pattern, used via as_manager().
    """

    def by_type(self, type: str, id: str, tenant: Tenant) -> "Subject":
        """Get a subject by type (for dynamic dispatch).

        Args:
            type: The subject type ('group' or 'user')
            id: The subject UUID
            tenant: The tenant context

        Returns:
            Subject wrapping the Group or Principal

        Raises:
            RequiredFieldError: If id is empty
            UnsupportedSubjectTypeError: If the type is not supported
            NotFoundError: If the subject cannot be found
        """
        from management.subject.exceptions import UnsupportedSubjectTypeError
        from management.subject.model import SubjectType

        if not id:
            raise RequiredFieldError("subject_id")

        if type == SubjectType.GROUP:
            return self.group(id=id, tenant=tenant)
        elif type == SubjectType.USER:
            return self.user(id=id, tenant=tenant)
        raise UnsupportedSubjectTypeError(type)

    def group(self, id: str, tenant: Tenant) -> "Subject":
        """Get a group subject by UUID.

        Args:
            id: The group UUID
            tenant: The tenant context (unused for groups, but kept for consistency)

        Returns:
            Subject wrapping the Group

        Raises:
            NotFoundError: If the group cannot be found
        """
        from management.subject.model import Subject, SubjectType

        try:
            entity = Group.objects.annotate(
                principalCount=Count("principals", filter=Q(principals__type=Principal.Types.USER), distinct=True)
            ).get(uuid=id)
            return Subject(type=SubjectType.GROUP, entity=entity)
        except Group.DoesNotExist:
            raise NotFoundError(SubjectType.GROUP, id)

    def user(self, id: str, tenant: Tenant) -> "Subject":
        """Get a user subject by UUID.

        Args:
            id: The user/principal UUID
            tenant: The tenant context for the lookup

        Returns:
            Subject wrapping the Principal

        Raises:
            NotFoundError: If the principal cannot be found
        """
        from management.subject.model import Subject, SubjectType

        try:
            entity = Principal.objects.get(uuid=id, tenant=tenant)
            return Subject(type=SubjectType.USER, entity=entity)
        except Principal.DoesNotExist:
            raise NotFoundError(SubjectType.USER, id)

    @classmethod
    def as_manager(cls) -> "SubjectQuerySet":
        """Return a manager instance, following Django's pattern."""
        return cls()
