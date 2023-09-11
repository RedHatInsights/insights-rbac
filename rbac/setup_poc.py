# script for setting up workspaces and permissions
# setup workspaces and workspace heirarchy
# for running with docker-compose
import os
import time
import sys
import django
print("setting up django")

sys.path.insert(0, os.path.abspath("../../rbac/"))
os.environ["DJANGO_SETTINGS_MODULE"] = "rbac.settings"
django.setup()

import requests
from api.models import Tenant
from management.models import Access, Permission, Workspace, Role, Principal


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
        print("response:")
        print(json_response)
        for dictobject in child.items():
            create_workspaces(par_uuid, dictobject[0], dictobject[1])


def set_workspace_permissions(workspace_permissions):
    for workspace, perms in workspace_permissions.items():
        print("\n\nworkspace: ")
        worksp_obj = Workspace.objects.filter(name=workspace).first()
        print(worksp_obj)
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
        group_principal_url = group_url + f"{group_uuid}/principals/"
        print("\n\n\njson response: ")
        print(json_response)
        print(group_principal_url)
        prince_response = requests.post(group_principal_url, json={"principals": [{'username': 'user_dev'}]}, headers={"Content-Type": "application/json"})
        print("\n\n\nprince_response: ")
        print(prince_response)
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
    print(f"tenant now exists: {prince.username}")

create_principal()
time.sleep(3)
create_workspaces(None, 'Support', workspaces['Support'])
time.sleep(2)
set_workspace_permissions(workspace_perms)
time.sleep(3)
create_groups(workspace_groups)
time.sleep(2)
create_access(access_perms)


# create roles from permissions

# create groups

# add roles to groups

# print list of curl commands to check the