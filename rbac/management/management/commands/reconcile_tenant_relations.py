#
# Copyright 2021 Red Hat, Inc.
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
"""Reconcile tenant relations command."""
import logging

from django.apps import apps
from django.core.management.base import BaseCommand
from tenant_schemas.utils import tenant_context

from api.models import Tenant

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Command(BaseCommand):
    """Command class for reconciling/querying tenant_ids on objects."""

    help = "Reconciles the tenant_id relations on RBAC objects"

    def add_arguments(self, parser):
        """Add arguments to command."""
        parser.add_argument("--readonly", action="store_true")

    def models_with_tenant_relations(self):
        """Return models with tenant relations."""
        return ["ResourceDefinition", "Access", "Role", "Principal", "Policy", "Group", "Permission"]

    def handle(self, *args, **options):
        """Handle method for command."""
        read_only = options["readonly"]
        tenants = Tenant.objects.all()
        tenants_missing_releations = set()

        try:
            for idx, tenant in enumerate(list(tenants)):
                with tenant_context(tenant):
                    tenant_id = tenant.id
                    tenant_name = tenant.schema_name
                    logger.info(
                        f"*** Syncing Tenant '{tenant_id}' - '{tenant_name}' ({idx + 1} of {len(tenants)}) ***"
                    )
                    for model in self.models_with_tenant_relations():
                        tenant_misses = 0
                        klass = apps.get_model("management", model)
                        records = klass.objects.filter(tenant__isnull=True)
                        for record in records:
                            if not read_only:
                                try:
                                    logger.info(
                                        f"Setting tenant '{tenant_id}' - '{tenant_name}' on {model} '{record.id}'"
                                    )
                                    record.tenant = tenant
                                    record.save()
                                except Exception as e:
                                    logger.error(f"Failed to update record: {str(e)}")
                            else:
                                tenant_misses += 1
                        if tenant_misses > 0:
                            tenants_missing_releations.add(f"{tenant_name}:{tenant_id}")
                            logger.info(f"{tenant_misses} {model} objects without a tenant")

            logger.info("--- SUMMARY ---")
            if len(tenants_missing_releations) > 0:
                logger.info(f"Tenants with records needing a tenant_id: {list(tenants_missing_releations)}")
            else:
                logger.info("All tenant relations are set!")
        except Exception as e:
            logger.error(f"Failure: {str(e)}")
