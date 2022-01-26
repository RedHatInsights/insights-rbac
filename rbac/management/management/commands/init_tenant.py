#
# Copyright 2019 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Seeds command."""
import logging

from django.core.management.base import BaseCommand
from django.db import transaction
from management.group.definer import seed_group
from management.role.definer import seed_permissions, seed_roles
from tenant_schemas.utils import tenant_context

from api.models import Tenant

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Command(BaseCommand):
    """Command class for running seeds."""

    help = "Initialize a tenant: create a schema, migrate and seed."

    def add_arguments(self, parser):
        """Add arguments to command."""
        parser.add_argument("tenant_schema_name")

    def handle(self, *args, **options):
        """Handle method for command."""
        tenant_schema_name = options["tenant_schema_name"]

        try:
            tenant = Tenant.objects.get(schema_name=tenant_schema_name)
            with transaction.atomic():
                with tenant_context(tenant):
                    created = tenant.create_schema(check_if_exists=True)
                    if created is not False:
                        seed_permissions(tenant=tenant)
                        seed_roles(tenant=tenant)
                        seed_group(tenant=tenant)
                    tenant.ready = True
                    tenant.save()
        except Tenant.DoesNotExist:
            logger.error(f"Tenant `{tenant_schema_name}` does not exist.")
