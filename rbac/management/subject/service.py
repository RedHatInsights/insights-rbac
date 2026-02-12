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
"""Service layer for subject operations."""

from enum import StrEnum

from django.db.models import Count, Q
from management.exceptions import NotFoundError
from management.group.model import Group
from management.principal.model import Principal
from management.subject.exceptions import UnsupportedSubjectTypeError
from management.tenant_mapping.model import Tenant


class SubjectType(StrEnum):
    """Valid subject types for role bindings.

    This is a domain enum representing the types of subjects that can be
    assigned roles via role bindings.
    """

    GROUP = "group"
    USER = "user"

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Check if a value is a valid subject type."""
        return value in cls._value2member_map_

    @classmethod
    def values(cls) -> list[str]:
        """Return list of all valid subject type values."""
        return list(cls._value2member_map_.keys())


class SubjectService:
    """Service for subject-related operations.

    This service provides methods for retrieving and validating subjects
    (groups and users/principals) in the RBAC system.
    """

    def __init__(self, tenant: Tenant):
        """Initialize the service with a tenant context.

        Args:
            tenant: The tenant context for subject lookups
        """
        self.tenant = tenant

    def get_group(self, subject_id: str) -> Group:
        """Get a group by UUID.

        Args:
            subject_id: The group UUID

        Returns:
            The Group object with principal count annotation

        Raises:
            NotFoundError: If the group cannot be found
        """
        try:
            return Group.objects.annotate(
                principalCount=Count("principals", filter=Q(principals__type=Principal.Types.USER), distinct=True)
            ).get(uuid=subject_id)
        except Group.DoesNotExist:
            raise NotFoundError(SubjectType.GROUP, subject_id)

    def get_principal(self, subject_id: str) -> Principal:
        """Get a principal (user) by UUID.

        Args:
            subject_id: The principal UUID

        Returns:
            The Principal object

        Raises:
            NotFoundError: If the principal cannot be found
        """
        try:
            return Principal.objects.get(uuid=subject_id, tenant=self.tenant)
        except Principal.DoesNotExist:
            raise NotFoundError(SubjectType.USER, subject_id)

    def get_subject(self, subject_type: str, subject_id: str) -> Group | Principal:
        """Get a subject by type and ID.

        Args:
            subject_type: The type of subject ('group' or 'user')
            subject_id: The subject UUID

        Returns:
            The subject (Group or Principal)

        Raises:
            UnsupportedSubjectTypeError: If the subject type is not supported
            NotFoundError: If the subject cannot be found
        """
        if subject_type == SubjectType.GROUP:
            return self.get_group(subject_id)
        elif subject_type == SubjectType.USER:
            return self.get_principal(subject_id)
        else:
            raise UnsupportedSubjectTypeError(subject_type)
