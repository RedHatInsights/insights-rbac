"""
Copyright 2019 Red Hat, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


def create_tenant_relationships(tenant):
    """Create relationships for tenant."""
    pass


def create_user_relationships(principal, is_org_admin):
    """Create relationships for user."""
    pass


def remove_user_relationships(tenant, groups, principal, is_org_admin):
    """Remove relationships for user."""
    # TODO: consider (admin) default groups
    pass
