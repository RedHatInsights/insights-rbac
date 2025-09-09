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

"""Model for permission management."""
import dataclasses
from django.db import models

from api.models import TenantAwareModel


@dataclasses.dataclass(frozen=True)
class _PermissionDescriptor:
    """
    Represents the value of a single permission.

    A permission consists of an app name, a resource type name, and a verb.

    The resource type and verb may either be normal strings or the wildcard '*'.
    If either component contains a wildcard, it must be the entire component.
    (That is, 'foo*' is not a glob.) The app name may not be a wildcard.

    No component may contain a colon in order to ensure the string representation
    remains unambiguous.
    """

    app: str
    resource: str
    verb: str

    @staticmethod
    def _check_valid_component(name: str, value: str):
        """
        Check that the component is valid in a permission.

        Name is used for producing error messages.
        """
        if value is None:
            raise ValueError(f"{name} cannot be None")

        if ":" in value:
            raise ValueError(f"Portions of a permission cannot contain colons, but got {name}: {value}")

        if (value != "*") and ("*" in value):
            raise ValueError(f"Wildcard portions of a permission must be only an asterisk, but got {name}: {value}")

    def __post_init__(self):
        """Verify that this permission is valid."""
        if "*" in self.app:
            raise ValueError("Wildcards are not permitted in the app portion of permissions.")

        self._check_valid_component("app", self.app)
        self._check_valid_component("resource", self.resource)
        self._check_valid_component("action", self.verb)

    @classmethod
    def parse_v1(cls, permission_str: str) -> "_PermissionDescriptor":
        """Parse a V1 permission string, e.g. app:resource:verb."""
        parts = permission_str.split(":")

        if len(parts) != 3:
            raise ValueError(f"Permission string must contain three colon-separated parts: {permission_str}")

        return cls(app=parts[0], resource=parts[1], verb=parts[2])

    def with_unconstrained_resource(self) -> "_PermissionDescriptor":
        """Return a new permission with a wildcard resource."""
        return _PermissionDescriptor(
            app=self.app,
            resource="*",
            verb=self.verb,
        )

    def with_unconstrained_verb(self) -> "_PermissionDescriptor":
        """Return a new permission with a wildcard verb."""
        return _PermissionDescriptor(
            app=self.app,
            resource=self.resource,
            verb="*",
        )

    def with_app_only(self) -> "_PermissionDescriptor":
        """Return a new permission with a wildcard resource and verb."""
        return _PermissionDescriptor(
            app=self.app,
            resource="*",
            verb="*",
        )

    def v1_string(self) -> str:
        """Return the V1 representation of this permission: app:resource:verb."""
        return f"{self.app}:{self.resource}:{self.verb}"


class Permission(TenantAwareModel):
    """A Permission."""

    application = models.TextField(null=False)
    resource_type = models.TextField(null=False)
    verb = models.TextField(null=False)
    permission = models.TextField(null=False, unique=True)
    description = models.TextField(default="")
    permissions = models.ManyToManyField("self", symmetrical=False, related_name="requiring_permissions")

    def save(self, *args, **kwargs):
        """Populate the application, resource_type and verb field before saving."""
        context = self.permission.split(":")
        self.application = context[0]
        self.resource_type = context[1]
        self.verb = context[2]
        super(Permission, self).save(*args, **kwargs)
