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
