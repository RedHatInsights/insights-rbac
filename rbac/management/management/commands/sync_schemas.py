from django.db import connection
from django.core.management.base import BaseCommand
from management.models import Group, Role, Policy, Principal
from api.models import Tenant
from tenant_schemas.utils import tenant_context


class Command(BaseCommand):
    help = "Syncs custom principals, roles, groups, and policies to the public schema"


    def copy_custom_principals_to_public(self, tenant):
        principals = Principal.objects.all()
        public_schema = Tenant.objects.get(schema_name="public")
        for principal in principals:
            print(f"Copying principal {principal.username} to public schema for tenant {tenant}.")
            if not principal.tenant:
                principal.tenant = tenant
                principal.save()
            with tenant_context(public_schema):
                principal.id = None
                principal.pk = None
                principal.save()


    def copy_custom_roles_to_public(self, tenant):
        roles = Role.objects.filter(system=False)
        public_schema = Tenant.objects.get(schema_name="public")
        for role in roles:
            print(f"Copying role {role.name} to public schema for tenant {tenant}.")
            if not role.tenant:
                role.tenant = tenant
                role.save()
            access_list = list(role.access.all())
            with tenant_context(public_schema):
                role.id = None
                role.pk = None
                role.save()
                for access in access_list:
                    access.id = None
                    access.pk = None
                    if not access.tenant:
                        access.tenant = tenant
                        access.role = role
                    access.save()
                    for resource_def in access.resourceDefinitions.all():
                        resource_def.id = None
                        resource_def.pk = None
                        resource_def.access = access
                        resource_def.save()
                role.access.set(access_list)
                role.save()


    def copy_custom_groups_to_public(self, tenant):
        groups = Group.objects.filter(system=False)
        public_schema = Tenant.objects.get(schema_name="public")
        for group in groups:
            print(f"Copying group {group.name} to public schema for tenant {tenant}.")
            if not group.tenant:
                group.tenant = tenant
                group.save()
            principals = list(group.principals.all())
            new_principals = []
            with tenant_context(public_schema):
                group.pk = None
                group.id = None
                group.save()
                for principal in principals:
                    new_principals.append(Principal.objects.get(username=principal.username))
                group.principals.set(new_principals)
                group.save()


    def copy_custom_policies_to_public(self, tenant):
        policies = Policy.objects.all()
        public_schema = Tenant.objects.get(schema_name="public")
        for policy in policies:
            print(f"Copying policy {policy.name} to public schema for tenant {tenant}.")
            if not policy.tenant:
                policy.tenant = tenant
                policy.save()
            group = policy.group
            roles = list(policy.roles.all())
            new_roles = []
            with tenant_context(public_schema):
                policy.fk = None
                policy.id = None
                policy.save()
                policy.group = Group.objects.get(name=group.name)
                for role in roles:
                    new_roles.append(Role.objects.get(name=role.name))
                policy.roles.set(new_roles)
                policy.save()


    def handle(self, *args, **options):
        tenants = Tenant.objects.exclude(schema_name="public")
        print(tenants)
        for tenant in tenants:
            with tenant_context(tenant):
                self.copy_custom_principals_to_public(tenant)
                self.copy_custom_roles_to_public(tenant)
                self.copy_custom_groups_to_public(tenant)
                self.copy_custom_policies_to_public(tenant)
