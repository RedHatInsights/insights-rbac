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
from management.seeds import (
    group_seeding,
    permission_seeding,
    role_binding_group_seeding,
    role_binding_seeding,
    role_seeding,
    v2_role_seeding,
    workspace_seeding,
)

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Command(BaseCommand):
    """Command class for running seeds."""

    help = "Runs the seeding for roles, V2 roles, workspaces, permissions, groups, and role bindings"

    def add_arguments(self, parser):
        """Add arguments to command."""
        parser.add_argument("--permissions", action="store_true")
        parser.add_argument("--roles", action="store_true")
        parser.add_argument("--groups", action="store_true")
        parser.add_argument("--workspaces", action="store_true")
        parser.add_argument("--v2_roles", action="store_true")
        parser.add_argument("--role_bindings", action="store_true")
        parser.add_argument("--role_binding_groups", action="store_true")
        parser.add_argument("--force-create-relationships", action="store_true")

    def handle(self, *args, **options):
        """Handle method for command."""
        seed_all = not (options["permissions"] or options["roles"] or options["groups"])

        if options["permissions"] or seed_all:
            logger.info("*** Seeding permissions... ***")
            permission_seeding()
            logger.info("*** Permission seeding completed. ***\n")

        if options["roles"] or seed_all:
            logger.info("*** Seeding roles... ***")
            logger.info(f"Running with force-create-relationships: {options.get('force_create_relationships', False)}")
            role_seeding(options.get("force_create_relationships", False))
            logger.info("*** Role seeding completed. ***\n")

        if options["v2_roles"] or seed_all:
            logger.info("*** Seeding V2 Roles... ***")
            v2_role_seeding()
            logger.info("*** V2 Roles seeding completed. ***\n")

        if options["role_bindings"] or seed_all:
            logger.info("*** Seeding V2 Role bindings... ***")
            role_binding_seeding()
            logger.info("*** V2 Role bindings seeding completed. ***\n")

        if options["role_binding_groups"] or seed_all:
            logger.info("*** Seeding V2 Role binding groups... ***")
            role_binding_group_seeding()
            logger.info("*** V2 Role binding groups seeding completed. ***\n")

        if options["groups"] or seed_all:
            logger.info("*** Seeding groups... ***")
            group_seeding()
            logger.info("*** Group seeding completed. ***\n")

        if options["workspaces"] or seed_all:
            logger.info("*** Seeding workspaces... ***")
            workspace_seeding()
            logger.info("*** Workspace seeding completed. ***\n")

        # Since the cache will expire in 10 min. We can let it expire by itself. Not worth to explicitly expire it
        # currently becuthere might be some other unexpected issues. Can enable it in the future if it becomes an issue.
        # purge_cache_for_all_tenants()
