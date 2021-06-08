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
"""Schema sync command."""

from django.core.management.base import BaseCommand
from django.db.utils import IntegrityError
from management.models import Group, Policy, Principal, Role
from tenant_schemas.utils import tenant_context

from api.models import Tenant


class Command(BaseCommand):
    """Command for use with django's manage.py script."""

    help = "Syncs custom principals, roles, groups, and policies to the public schema"

    def clear_pk(self, entry):
        """Clear the ID and PK values for provided postgres entry."""
        entry.id = None
        entry.pk = None

    def copy_custom_principals_to_public(self, tenant):
        """Copy custom principals from provided tenant to the public schema."""
        principals = Principal.objects.all()
        public_schema = Tenant.objects.get(schema_name="public")
        for principal in principals:
            self.stdout.write(f"Copying principal {principal.username} to public schema for tenant {tenant}.")
            if not principal.tenant:
                principal.tenant = tenant
                principal.save()
            with tenant_context(public_schema):
                self.clear_pk(principal)
                try:
                    principal.save()
                except IntegrityError as err:
                    self.stderr.write(f"Couldn't copy principal: {principal.username}. Skipping due to:\n{err}")
                    continue

    def copy_custom_roles_to_public(self, tenant):
        """Copy custom roles from provided tenant to the public schema."""
        roles = Role.objects.filter(system=False)
        public_schema = Tenant.objects.get(schema_name="public")
        for role in roles:
            self.stdout.write(f"Copying role {role.name} to public schema for tenant {tenant}.")
            if not role.tenant:
                role.tenant = tenant
                role.save()
            access_list = list(role.access.all())
            with tenant_context(public_schema):
                self.clear_pk(role)
                try:
                    role.save()
                except IntegrityError as err:
                    self.stderr.write(f"Couldn't copy role: {role.name}. Skipping due to:\n{err}")
                    continue
                for access in access_list:
                    self.clear_pk(access)
                    if not access.tenant:
                        access.tenant = tenant
                    access.role = role
                    try:
                        access.save()
                    except IntegrityError as err:
                        self.stderr.write(f"Couldn't copy access entry: {access}. Skipping due to:\n{err}")
                        continue
                    for resource_def in access.resourceDefinitions.all():
                        self.clear_pk(resource_def)
                        resource_def.access = access
                        try:
                            resource_def.save()
                        except IntegrityError as err:
                            self.stderr.write(f"Couldn't copy {resource_def}. Skipping due to:\n{err}")
                            continue
                role.access.set(access_list)
                role.save()

    def copy_custom_groups_to_public(self, tenant):
        """Copy custom groups from provided tenant to the public schema."""
        groups = Group.objects.filter(system=False)
        public_schema = Tenant.objects.get(schema_name="public")
        for group in groups:
            self.stdout.write(f"Copying group {group.name} to public schema for tenant {tenant}.")
            if not group.tenant:
                group.tenant = tenant
                group.save()
            principals = list(group.principals.all())
            new_principals = []
            with tenant_context(public_schema):
                self.clear_pk(group)
                try:
                    group.save()
                except IntegrityError as err:
                    self.stderr.write(f"Couldn't copy group {group.name}. Skipping due to:\n{err}")
                    continue
                for principal in principals:
                    new_principals.append(Principal.objects.get(username=principal.username, tenant=tenant))
                group.principals.set(new_principals)
                group.save()

    def copy_custom_policies_to_public(self, tenant):
        """Copy custom policies from provided tenant to the public schema."""
        policies = Policy.objects.all()
        public_schema = Tenant.objects.get(schema_name="public")
        for policy in policies:
            self.stdout.write(f"Copying policy {policy.name} to public schema for tenant {tenant}.")
            if not policy.tenant:
                policy.tenant = tenant
                policy.save()
            group = policy.group
            if group.system:
                continue
            roles = list(policy.roles.all())
            new_roles = []
            with tenant_context(public_schema):
                policy.roles.clear()
                policy.group = None
                self.clear_pk(policy)
                try:
                    policy.save()
                except IntegrityError as err:
                    self.stderr.write(f"Couldn't copy policy {policy.name}. Skipping due to:\n{err}")
                    continue
                else:
                    policy.group = Group.objects.get(name=group.name, tenant=tenant)
                    for role in roles:
                        new_roles.append(Role.objects.get(name=role.name, tenant=tenant))
                policy.roles.set(new_roles)
                policy.save()

    def handle(self, *args, **options):
        """Actually do the work when the command is run."""
        tenants = Tenant.objects.exclude(schema_name="public")
        try:
            for idx, tenant in enumerate(list(tenants)):
                self.stdout.write(
                    f"*** Syncing Schemas for '{tenant.id}' - '{tenant.schema_name}' ({idx + 1} of {len(tenants)}) ***"
                )
                with tenant_context(tenant):
                    self.copy_custom_principals_to_public(tenant)
                    self.copy_custom_roles_to_public(tenant)
                    self.copy_custom_groups_to_public(tenant)
                    self.copy_custom_policies_to_public(tenant)
        except Exception as e:
            self.stderr(f"Failure: {str(e)}")
