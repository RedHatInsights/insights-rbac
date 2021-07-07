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

import traceback

from django.core.management.base import BaseCommand
from django.db.utils import IntegrityError
from management.models import Group, Permission, Policy, Principal, Role
from management.utils import clear_pk
from tenant_schemas.utils import tenant_context

from api.models import Tenant


class Command(BaseCommand):
    """Command for use with django's manage.py script."""

    help = "Syncs custom principals, roles, groups, and policies to the public schema"

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
                clear_pk(principal)
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
            access_perms = []
            for access in access_list:
                access_perms.append(access.permission.permission)
            self.stdout.write(f"Access Strings:\n{access_perms}")
            access_resourceDefs = {}
            for access in access_list:
                access_resourceDefs[str(access)] = list(access.resourceDefinitions.all())
            self.stdout.write(f"Accesses to copy: {access_list}")
            with tenant_context(public_schema):
                clear_pk(role)
                try:
                    role.save()
                except IntegrityError as err:
                    self.stderr.write(f"Couldn't copy role: {role.name}. Skipping due to:\n{err}")
                    continue
                for access in access_list:
                    old_access = str(access)
                    clear_pk(access)
                    if not access.tenant:
                        access.tenant = tenant
                    access.role = role
                    try:
                        access.permission = Permission.objects.get(permission=access.permission.permission)
                    except Permission.DoesNotExist as err:
                        self.stderr.write(f"Couldn't find permission entry: {access.permission.permission}, skipping.")
                        self.stderr.write(f"Additional context:\n {err}")
                        access_list.remove(access)
                        continue
                    try:
                        access.save()
                        self.stdout.write(f"Copy access with perm {access.permission.permission}")
                    except IntegrityError as err:
                        self.stderr.write(f"Couldn't copy access entry: {access}. Skipping due to:\n{err}")
                        continue
                    for resource_def in access_resourceDefs[old_access]:
                        clear_pk(resource_def)
                        resource_def.access = access
                        try:
                            resource_def.save()
                            self.stdout.write(f"Copied resource definition with filter {resource_def.attributeFilter}")
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
                clear_pk(group)
                try:
                    group.save()
                except IntegrityError as err:
                    self.stderr.write(f"Couldn't copy group {group.name}. Skipping due to:\n{err}")
                    continue
                for principal in principals:
                    new_principals.append(Principal.objects.get(username=principal.username, tenant=tenant))
                group.principals.set(new_principals)
                group.save()

    def copy_custom_permissions_to_public(self, tenant):
        """Copy custom permissions from provided tenant to the public schema."""
        new_permissions = []
        public_schema = Tenant.objects.get(schema_name="public")
        with tenant_context(public_schema):
            public_permissions = list(Permission.objects.values("permission"))

        tenant_permissions = Permission.objects.values("permission")
        for perm in tenant_permissions:
            if perm not in public_permissions:
                new_permissions.append(Permission.objects.get(permission=perm["permission"]))

        with tenant_context(public_schema):
            for new_perm in new_permissions:
                self.stdout.write(f"Copying permission {new_perm.permission} to public schema for tenant {tenant}.")
                clear_pk(new_perm)
                try:
                    new_perm.save()
                except IntegrityError as err:
                    self.stderr.write(f"Couldn't copy permission {new_perm.permission}. Skipping due to:\n{err}")
                    continue

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
            group_name = group.name
            if group.system:
                continue
            roles = list(policy.roles.all())
            tenant_roles = []
            for role in roles:
                tenant_roles.append({"name": role.name, "system": role.system})
            new_roles = []
            with tenant_context(public_schema):
                policy.group = None
                clear_pk(policy)
                policy.group = None
                try:
                    policy.save()
                except IntegrityError as err:
                    self.stderr.write(f"Couldn't copy policy {policy.name}. Skipping due to:\n{err}")
                    continue
                else:
                    policy.group = Group.objects.get(name=group_name, tenant=tenant)
                    for role in tenant_roles:
                        if role.get("system"):
                            new_roles.append(Role.objects.get(name=role.get("name"), tenant=public_schema))
                        else:
                            new_roles.append(Role.objects.get(name=role.get("name"), tenant=tenant))
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
                    self.copy_custom_permissions_to_public(tenant)
                    self.copy_custom_roles_to_public(tenant)
                    self.copy_custom_groups_to_public(tenant)
                    self.copy_custom_policies_to_public(tenant)
        except Exception as e:
            self.stderr.write(f"Failed during copying schemas. Error was: {e}")
            self.stderr.write(f"Trace: {''.join(traceback.format_exception(type(e), e, e.__traceback__))}")
