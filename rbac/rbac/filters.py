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

"""Custom RBAC Filters."""
import logging
import threading


local = threading.local()  # pylint: disable=invalid-name


class ContextFilter(logging.Filter):  # pylint: disable=too-few-public-methods
    """Provide log record attributes around request usage."""

    def filter(self, record):
        """Add filtered information to log records based on thread context.

        Args:
            record (object): The log record object
        """
        account = None
        username = None
        is_admin = None
        req_id = None
        if hasattr(local, 'account'):
            account = local.account
        if hasattr(local, 'username'):
            username = local.username
        if hasattr(local, 'is_admin'):
            is_admin = local.is_admin
        if hasattr(local, 'req_id'):
            req_id = local.req_id
        record.account_id = account
        record.username = username
        record.is_admin = is_admin
        record.req_id = req_id
        return True
