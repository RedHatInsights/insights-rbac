# script for setting up workspaces and permissions
# setup workspaces and workspace heirarchy
# for running with docker-compose
import os
import sys
import django
print("setting up django")

sys.path.insert(0, os.path.abspath("../../rbac/"))
os.environ["DJANGO_SETTINGS_MODULE"] = "rbac.settings"
django.setup()

import requests
from management.models import Access, Permission, Workspace, Role, Principal, Group
from os import environ as e

import psycopg2

# to show the structure
workspaces = {
    'Support': [{'Support_team1': [{'Support_subteam1': []}]}, {'Support_team2': []}]
}

workspace_perms = {
    'Support': ['openshift:cluster:read', 'openshift:cluster:write'],
    'Support_team1': ['rhel:host:read'],
    'Support_team2': ['satellite:host:read'],
    'Support_subteam1': ['rhel:host:write']
}

workspace_groups = {
    'Support': ['Openshift ARB'],
    'Support_team1': ['RHEL ARB read role'],
    'Support_team2': ['Satellite ARB read role'],
    'Support_subteam1': ['RHEL ARB write role']
}

access_perms = {
    'Openshift ARB': ['openshift:cluster:read', 'openshift:cluster:write'],
    'RHEL ARB read role': ['rhel:host:read'],
    'Satellite ARB read role': ['satellite:host:read'],
    'RHEL ARB write role': ['rhel:host:write']
}

def create_workspaces(parent_uuid, name, children):
    """
    Takes in a structure of parent/child workspaces and creates the tree
    """
    workspace_url = "http://127.0.0.1:9080/api/rbac/v1/workspaces/"
    if parent_uuid:
        workspace_url += f"{parent_uuid}/children/"
    response = requests.post(workspace_url, json={"name": name}, headers={"Content-Type": "application/json"})
    print(f"\nCreated {name} workspace at {workspace_url}")
    for child in children:
        json_response = response.json()
        par_uuid = json_response.get("uuid")
        for dictobject in child.items():
            create_workspaces(par_uuid, dictobject[0], dictobject[1])


def set_workspace_permissions(workspace_permissions):
    for workspace, perms in workspace_permissions.items():
        worksp_obj = Workspace.objects.filter(name=workspace).first()
        # look up the permissions and set the workspace id
        for permission in perms:
            perm_obj = Permission.objects.filter(permission=permission).first()
            perm_obj.workspace_id = worksp_obj.id
            perm_obj.tenant_id = 2
            perm_obj.save()
            print(f"Added permission {perm_obj.permission} to workspace {workspace}")

def create_groups(workspace_groups):
    for group, roles in workspace_groups.items():
        group_url = "http://127.0.0.1:9080/api/rbac/v1/groups/"
        print(f"\nCreating group {group}")
        response = requests.post(group_url, json={"name": group, "description": "test group"}, headers={"Content-Type": "application/json"})
        json_response = response.json()
        group_uuid = json_response.get("uuid")

        for role in roles:
            role_obj = Role.objects.filter(name=role).first()
            role_obj.tenant_id = 2
            role_obj.save()
            role_url = group_url + f"{group_uuid}/roles/"
            response = requests.post(role_url, json={"roles": [str(role_obj.uuid)]}, headers={"Content-Type": "application/json"})
            print(f"\nAdded role {role} to group {group}")

def create_access(access_perms):
    for role, perms in access_perms.items():
        role_obj = Role.objects.filter(name=role).first()
        for perm in perms:
            perm_obj = Permission.objects.filter(permission=perm).first()
            access_obj = Access(role_id=role_obj.id, permission_id=perm_obj.id, tenant_id=2)
            access_obj.save()

def create_principal():
    prince = Principal(username="user_dev", cross_account=False, tenant_id=2)
    prince.save()
    prince = Principal.objects.filter(username="user_dev").first()
    print(f"Principal now exists: {prince.username}")

def tie_principal_to_groups(workspace_groups):
    config = "dbname='%s' user='%s' host='%s' port='%s' password='%s'"

    name, user, host, port = (
        e["DATABASE_NAME"],
        e["DATABASE_USER"],
        e["DATABASE_HOST"],
        e["DATABASE_PORT"]
    )

    for group, _ in workspace_groups.items():
        group_obj = Group.objects.filter(name=group).first()
        group_id = group_obj.id
        principal_obj = Principal.objects.filter(username="user_dev").first()
        principal_id = principal_obj.id
        print(f"\n Group id {group_id}: ")
        conn = psycopg2.connect(config % (name, "postgres", host, port, "postgres"))
        conn.set_isolation_level(0)
        cur = conn.cursor()
        mySql_insert_query = """INSERT INTO management_group_principals (group_id, principal_id)
                                VALUES (%s, %s)"""

        record = (group_id, principal_id)
        cur.execute(mySql_insert_query, record)
        conn.commit()
        print("Record inserted successfully into management_principal_group table")

create_principal()
create_workspaces(None, 'Support', workspaces['Support'])
set_workspace_permissions(workspace_perms)
create_groups(workspace_groups)
create_access(access_perms)
tie_principal_to_groups(workspace_groups)

print("Support workspace structure is set up & ready to use pdp endpoints: ")
usage = \
    "\n\nCheck the pdp demo by running the following:\n\n\tCheck if Support Workspace has Openshift cluster read permission:\n\tcurl 'http://127.0.0.1:9080/api/rbac/v1/access/?pdp=true&action=read&workspace=Support&service=openshift&resource_type=cluster'\n\n\tCheck if Support_team1 Workspace inherited Openshift cluster read permission:\n\tcurl 'http://127.0.0.1:9080/api/rbac/v1/access/?pdp=true&action=read&workspace=Support_team1&service=openshift&resource_type=cluster"
print(usage)