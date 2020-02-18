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
"""Django database settings."""
import os
from tempfile import NamedTemporaryFile

from django.conf import settings

from .env import ENVIRONMENT


def config():
    """Database config."""

    db_obj = {
        'ENGINE': 'tenant_schemas.postgresql_backend',
        'NAME': ENVIRONMENT.get_value('DATABASE_NAME', default=None),
        'USER': ENVIRONMENT.get_value('DATABASE_USER', default=None),
        'PASSWORD': ENVIRONMENT.get_value('DATABASE_PASSWORD', default=None),
        'HOST': ENVIRONMENT.get_value('DATABASE_HOST', default=None),
        'PORT': ENVIRONMENT.get_value('DATABASE_PORT', default=None),
    }

    database_cert = ENVIRONMENT.get_value('DATABASE_SERVICE_CERT', default=None)
    if database_cert:
        temp_cert_file = NamedTemporaryFile(delete=False, mode='w', suffix='pem')
        with open(temp_cert_file.name, mode='w') as cert_file:
            cert_file.write(database_cert)
        db_options = {
            'OPTIONS': {
                'sslmode': 'verify-full',
                'sslrootcert': temp_cert_file.name
            }
        }
        db_obj.update(db_options)

    return db_obj
