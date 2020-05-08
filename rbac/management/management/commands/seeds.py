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
from management.seeds import group_seeding, role_seeding

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Command(BaseCommand):
    """Command class for running seeds."""

    help = 'Runs the seeding for roles and groups'

    def handle(self, *args, **options):
        """Handle method for command."""
        logger.info('*** Seeding roles... ***')
        role_seeding()
        logger.info('*** Role seeding completed. ***\n')

        logger.info('*** Seeding groups... ***')
        group_seeding()
        logger.info('*** Group seeding completed. ***\n')
