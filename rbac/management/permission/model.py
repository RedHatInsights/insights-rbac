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
from django.db import models


class Permission(models.Model):
    """A Permission."""

    application = models.TextField(null=False)
    resource_type = models.TextField(null=False)
    verb = models.TextField(null=False)
    permission = models.TextField(null=False, unique=True)
    description = models.TextField(default="")

    def save(self, *args, **kwargs):
        """Populate the application, resource_type and verb field before saving."""
        context = self.permission.split(":")
        self.application = context[0]
        self.resource_type = context[1]
        self.verb = context[2]
        super(Permission, self).save(*args, **kwargs)
