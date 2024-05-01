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
from migration_tool.migrate import migrate_roles

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Command(BaseCommand):
    """Command class for running seeds."""

    help = "Runs the migration for roles from V1 to V2 spiceDB schema"

    def add_arguments(self, parser):
        """Parse command arguments."""
        parser.add_argument("--mode", type=str, default="exclude", help="Choice of include or exclude")
        parser.add_argument("--apps", type=str, nargs="+", default="", help="List of space separated apps to include or exclude")
        parser.add_argument("--orgs", type=str, nargs="+", default="", help="List of space separated org ids to include")

    def handle(self, *args, **options):
        """Handle method for command."""
        logger.info("*** Role migration started. ***\n")
        exclude = True if options["mode"] == "exclude" else False
        app_list = options["apps"].split(" ")
        org_list = options["orgs"].split(" ")
        migrate_roles(exclude, app_list, org_list)
