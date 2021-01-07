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
from .env import ENVIRONMENT
from app_common_python import LoadedConfig

def config():
    """Database config."""
    if ENVIRONMENT.bool("CLOWDER_ENABLED", default=False):
        db_obj = {
            "ENGINE": "tenant_schemas.postgresql_backend",
            "NAME": LoadedConfig.database.name,
            "USER": LoadedConfig.database.username,
            "PASSWORD": LoadedConfig.database.password,
            "HOST": LoadedConfig.database.hostname,
            "PORT": LoadedConfig.database.port,
        }
        if LoadedConfig.database.rdsCa:
            db_options = {
                "OPTIONS": {
                    "sslmode": ENVIRONMENT.get_value("PGSSLMODE", default="prefer"),
                    "sslrootcert": LoadedConfig.rds_ca(),
                }
            }
        else:
            db_options = {}
    else:
        db_obj = {
            "ENGINE": "tenant_schemas.postgresql_backend",
            "NAME": ENVIRONMENT.get_value("DATABASE_NAME", default=None),
            "USER": ENVIRONMENT.get_value("DATABASE_USER", default=None),
            "PASSWORD": ENVIRONMENT.get_value("DATABASE_PASSWORD", default=None),
            "HOST": ENVIRONMENT.get_value("DATABASE_HOST", default=None),
            "PORT": ENVIRONMENT.get_value("DATABASE_PORT", default=None),
        }
        db_options = {
            "OPTIONS": {
                "sslmode": ENVIRONMENT.get_value("PGSSLMODE", default="prefer"),
                "sslrootcert": ENVIRONMENT.get_value("PGSSLROOTCERT", default="/etc/rds-certs/rds-cacert"),
            }
        }

    db_obj.update(db_options)

    return db_obj
