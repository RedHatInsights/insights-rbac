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

"""Handler for system defined roles."""
import json
import logging
import os

from django.conf import settings
from management.role.model import Access, ResourceDefinition, Role
from tenant_schemas.utils import tenant_context

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def _make_role(tenant, data, update=False):
    """Create the role object in the database."""
    name = data.pop('name')
    description = data.pop('description', None)
    access_list = data.pop('access')
    version = data.pop('version', 1)
    version_diff = False
    if update:
        role, created = Role.objects.filter(name=name).get_or_create(name=name)
        version_diff = version != role.version
        if not created and version_diff:
            logger.info('Updating role %s for tenant %s.', name, tenant.schema_name)
            role.description = description
            role.system = True
            role.version = version
            role.save()
            role.access.all().delete()
    else:
        role = Role.objects.create(name=name,
                                   description=description,
                                   system=True,
                                   version=version)
        logger.info('Creating role %s for tenant %s.', name, tenant.schema_name)
    if not update or (update and version_diff):
        for access_item in access_list:
            resource_def_list = access_item.pop('resourceDefinitions', [])
            access_obj = Access.objects.create(**access_item, role=role)
            access_obj.save()
            for resource_def_item in resource_def_list:
                res_def = ResourceDefinition.objects.create(**resource_def_item, access=access_obj)
                res_def.save()
    return role


def _update_or_create_roles(tenant, roles, update=False):
    """Update or create roles from list."""
    for role_json in roles:
        _make_role(tenant, role_json, update)


def seed_roles(tenant, update=False):
    """For a tenant update or create system defined roles."""
    with tenant_context(tenant):
        roles_directory = os.path.join(settings.BASE_DIR, 'management', 'role', 'definitions')
        role_files = [f for f in os.listdir(roles_directory) if os.path.isfile(os.path.join(roles_directory, f))]
        for role_file_name in role_files:
            role_file_path = os.path.join(roles_directory, role_file_name)
            with open(role_file_path) as json_file:
                data = json.load(json_file)
                role_list = data.get('roles')
                _update_or_create_roles(tenant, role_list, update)
