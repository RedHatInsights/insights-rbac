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

import json
import uuid
from typing import Callable, FrozenSet, Type

from migration_tool.ingest import add_element
from migration_tool.models import (
    V1group,
    V1permission,
    V1resourcedef,
    V1role,
    V2boundresource,
    V2group,
    V2role,
    V2rolebinding,
)
from migration_tool.spicedb import cleanNameForV2SchemaCompatibility


Permissiongroupings = dict[V1resourcedef, list[str]]
Perm_bound_resources = dict[str, list[V2boundresource]]

group_perms_for_rolebinding_fn = Type[
    Callable[
        [str, Permissiongroupings, Perm_bound_resources, FrozenSet[V1group]],
        FrozenSet[V2rolebinding],
    ]
]

system_roles = {}


def add_system_role(role: V2role):
    """Add a system role to the system role map."""
    system_roles[frozenset(role.permissions)] = role


# Cost management system roles (do not currently exist, authored to represent cost
# management permissions: https://github.com/project-koku/koku/blob/main/koku/koku/rbac.py#L25 )

add_system_role(V2role("cost_administrator", frozenset(["cost_management_all_all"])))
add_system_role(
    V2role(
        "cost_price_list_administrator",
        frozenset(["cost_management_cost_model_all", "cost_management_settings_all"]),
    )
)
add_system_role(
    V2role(
        "cost_price_list_viewer",
        frozenset(["cost_management_cost_model_read", "cost_management_settings_read"]),
    )
)
add_system_role(
    V2role(
        "cost_cloud_viewer",
        frozenset(
            [
                "cost_management_aws_account_all",
                "cost_management_aws_organizational_unit_all",
                "cost_management_azure_subscription_guid_all",
                "cost_management_gcp_account_all",
                "cost_management_gcp_project_all",
                "cost_management_oci_payer_tenant_id_all",
            ]
        ),
    )
)
add_system_role(V2role("cost_openshift_viewer", frozenset(["cost_management_openshift_cluster_all"])))
add_system_role(V2role("cost_aws_acount_viewer", frozenset(["cost_management_aws_account_read"])))
add_system_role(
    V2role(
        "cost_aws_organizational_unit_viewer",
        frozenset(["cost_management_aws_organizational_unit_read"]),
    )
)
add_system_role(V2role("cost_gcp_account_viewer", frozenset(["cost_management_gcp_account_read"])))
add_system_role(V2role("cost_gcp_project_viewer", frozenset(["cost_management_gcp_project_read"])))
add_system_role(
    V2role(
        "cost_azure_subscription_viewer",
        frozenset(["cost_management_azure_subscription_guid_read"]),
    )
)
add_system_role(
    V2role(
        "cost_openshift_cluster_viewer",
        frozenset(["cost_management_openshift_cluster_read"]),
    )
)
add_system_role(V2role("cost_openshift_node_viewer", frozenset(["cost_management_openshift_node_read"])))
add_system_role(
    V2role(
        "cost_openshift_project_viewer",
        frozenset(["cost_management_openshift_project_read"]),
    )
)
add_system_role(
    V2role(
        "cost_model_admin",
        frozenset(["cost_management_cost_model_read", "cost_management_cost_model_write"]),
    )
)
add_system_role(V2role("cost_model_viewer", frozenset(["cost_management_cost_model_read"])))
add_system_role(
    V2role(
        "cost_setting_admin",
        frozenset(["cost_management_settings_read", "cost_management_settings_write"]),
    )
)
add_system_role(V2role("cost_setting_viewer", frozenset(["cost_management_settings_read"])))
add_system_role(
    V2role("cost_ibm_account_viewer", frozenset(["cost_management_ibm_account_read"]))
)  # NOTE- this isn't in the schema. May have been missed by schema generator if unused?
add_system_role(
    V2role(
        "cost_oci_tenant_payer_viewer",
        frozenset(["cost_management_oci_payer_tenant_id_read"]),
    )
)


# Inventory roles from: https://gitlab.corp.redhat.com/ciam-authz/loadtesting-spicedb/-/
# blob/main/spicedb/prbac-schema-generator/roles.zed?ref_type=heads#L196
add_system_role(V2role("inventory_administrator", frozenset(["inventory_all_all"])))
add_system_role(
    V2role(
        "inventory_hosts_administrator",
        frozenset(["inventory_hosts_read", "inventory_hosts_write"]),
    )
)
add_system_role(V2role("inventory_hosts_viewer", frozenset(["inventory_hosts_read"])))
add_system_role(
    V2role(
        "inventory_groups_administrator",
        frozenset(["inventory_groups_read", "inventory_groups_write"]),
    )
)
add_system_role(V2role("inventory_groups_viewer", frozenset(["inventory_groups_read"])))
add_system_role(
    V2role(
        "account_staleness_and_culling_administrator",
        frozenset(["inventory_staleness_read", "inventory_staleness_write"]),
    )
)
add_system_role(V2role("account_staleness_and_culling_viewer", frozenset(["inventory_staleness_read"])))

# Updated compliance roles from: https://github.com/RedHatInsights/rbac-config/blob/master/
# configs/prod/roles/compliance.json
add_system_role(
    V2role(
        "compliance_viewer",
        frozenset(
            [
                "compliance_policy_read",
                "compliance_report_read",
                "compliance_system_read",
                "remediations_remediation_read",
            ]
        ),
    )
)

add_system_role(
    V2role(
        "ansible_wisdom_admin_dashboard_user",
        frozenset(
            [
                "ansible_wisdom_admin_dashboard_chart_recommendations_read",
                "ansible_wisdom_admin_dashboard_chart_user_sentiment_read",
                "ansible_wisdom_admin_dashboard_chart_module_usage_read",
                "ansible_wisdom_admin_dashboard_chart_active_users_read",
            ]
        ),
    )
)
add_system_role(
    V2role(
        "automation_analytics_administrator",
        frozenset(["automation_analytics_all_all"]),
    )
)
add_system_role(
    V2role(
        "automation_analytics_editor",
        frozenset(["automation_analytics_all_read", "automation_analytics_all_write"]),
    )
)
add_system_role(V2role("automation_analytics_viewer", frozenset(["automation_analytics_all_read"])))
add_system_role(
    V2role(
        "compliance_administrator",
        frozenset(
            [
                "compliance_all_all",
                "remediations_remediation_read",
                "remediations_remediation_write",
            ]
        ),
    )
)
add_system_role(
    V2role(
        "compliance_viewer",
        frozenset(
            [
                "compliance_policy_read",
                "compliance_report_read",
                "compliance_system_read",
                "remediations_remediation_read",
            ]
        ),
    )
)
add_system_role(
    V2role(
        "rhc_administrator",
        frozenset(
            [
                "config_manager_activation_keys_all",
                "config_manager_state_read",
                "config_manager_state_write",
                "config_manager_state_changes_read",
                "playbook_dispatcher_config_manager_run_read",
                "subscriptions_organization_read",
            ]
        ),
    )
)
add_system_role(
    V2role(
        "rhc_viewer",
        frozenset(
            [
                "config_manager_activation_keys_read",
                "config_manager_activation_keys_write",
                "config_manager_state_read",
                "config_manager_state_changes_read",
                "playbook_dispatcher_config_manager_run_read",
            ]
        ),
    )
)
add_system_role(
    V2role(
        "repositories_administrator",
        frozenset(["content_sources_repositories_read", "content_sources_repositories_write"]),
    )
)
add_system_role(V2role("repositories_viewer", frozenset(["content_sources_repositories_read"])))

add_system_role(
    V2role(
        "drift_analysis_administrator",
        frozenset(
            [
                "drift_comparisons_read",
                "drift_baselines_read",
                "drift_baselines_write",
                "drift_historical_system_profiles_read",
                "drift_notifications_read",
                "drift_notifications_write",
                "drift_all_all",
            ]
        ),
    )
)
add_system_role(
    V2role(
        "drift_analysis_administrator",
        frozenset(
            [
                "drift_comparisons_read",
                "drift_baselines_read",
                "drift_baselines_write",
                "drift_historical_system_profiles_read",
                "drift_notifications_read",
                "drift_notifications_write",
            ]
        ),
    )
)
add_system_role(
    V2role(
        "drift_viewer",
        frozenset(
            [
                "drift_comparisons_read",
                "drift_baselines_read",
                "drift_historical_system_profiles_read",
                "drift_notifications_read",
            ]
        ),
    )
)
add_system_role(
    V2role(
        "hybrid_committed_spend_viewer",
        frozenset(["hybrid_committed_spend_reports_read"]),
    )
)
add_system_role(V2role("insights_administrator", frozenset(["advisor_all_all"])))
# Made-up system role
# add_system_role(V2role("insights-operator", frozenset(["advisor_exports_read",
# "advisor_disable_recommendations_write", "advisor_recommendation_results_read", "advisor_weekly_email_read"])))
add_system_role(V2role("malware_detection_administrator", frozenset(["malware_detection_all_all"])))
add_system_role(V2role("malware_detection_viewer", frozenset(["malware_detection_all_read"])))
add_system_role(
    V2role(
        "notifications_administrator",
        frozenset(["notifications_all_all", "integrations_all_all"]),
    )
)
# Made-up system role
# add_system_role(V2role("integrations_administrator", frozenset(["integrations_endpoints_read",
# "integrations_endpoints_write"]))) # Of note- the only thing that grants endpoints_write is notifications_admin
# Made-up system role
# add_system_role(V2role("notifications_user", frozenset(["notifications_notifications_read",
# "notifications_notifications_write", "notifications_events_read"])))
add_system_role(
    V2role(
        "notifications_viewer",
        frozenset(["notifications_notifications_read", "integrations_endpoints_read"]),
    )
)
add_system_role(V2role("ocp_advisor_administrator", frozenset(["ocp_advisor_all_all"])))
add_system_role(
    V2role(
        "patch_administrator",
        frozenset(["patch_all_all", "remediations_all_read", "remediations_all_write"]),
    )
)
add_system_role(V2role("patch_viewer", frozenset(["patch_all_read"])))
add_system_role(
    V2role(
        "policies_administrator",
        frozenset(["policies_policies_read", "policies_policies_write"]),
    )
)
add_system_role(V2role("policies_viewer", frozenset(["policies_policies_read"])))
add_system_role(V2role("launch_administrator", frozenset(["provisioning_all_all"])))
add_system_role(
    V2role(
        "launch_viewer",
        frozenset(
            [
                "provisioning_source_read",
                "provisioning_pubkey_read",
                "provisioning_reservation_read",
                "provisioning_reservation_aws_read",
                "provisioning_reservation_azure_read",
                "provisioning_reservation_gcp_read",
            ]
        ),
    )
)
add_system_role(
    V2role(
        "launch_on_aws_user",
        frozenset(
            [
                "provisioning_source_all",
                "provisioning_pubkey_all",
                "provisioning_reservation_all",
                "provisioning_reservation_aws_all",
            ]
        ),
    )
)
add_system_role(
    V2role(
        "launch_on_azure_user",
        frozenset(
            [
                "provisioning_source_all",
                "provisioning_pubkey_all",
                "provisioning_reservation_all",
                "provisioning_reservation_azure_all",
            ]
        ),
    )
)
add_system_role(
    V2role(
        "launch_on_google_cloud_user",
        frozenset(
            [
                "provisioning_source_all",
                "provisioning_pubkey_all",
                "provisioning_reservation_all",
                "provisioning_reservation_gcp_all",
            ]
        ),
    )
)
add_system_role(V2role("user_access_administrator", frozenset(["rbac_all_all"])))
add_system_role(V2role("user_access_principal_viewer", frozenset(["rbac_principal_read"])))
add_system_role(
    V2role(
        "remediations_administrator",
        frozenset(["remediations_all_all", "playbook_dispatcher_remediations_run_read"]),
    )
)
# Made-up system role -v
# add_system_role(V2role("remediations_operator", frozenset(["remediations_remediation_read",
# "remediations_remediation_write", "remediations_remediation_execute"])))
add_system_role(
    V2role(
        "remediations_user",
        frozenset(
            [
                "remediations_remediation_read",
                "remediations_remediation_write",
                "playbook_dispatcher_remediations_run_read",
            ]
        ),
    )
)
add_system_role(V2role("resource_optimization_administrator", frozenset(["ros_all_all"])))
add_system_role(V2role("resource_optimization_user", frozenset(["ros_all_read"])))
add_system_role(V2role("sources_administrator", frozenset(["sources_all_all"])))
add_system_role(
    V2role(
        "organization_staleness_and_deletion_administrator",
        frozenset(["staleness_staleness_write", "staleness_staleness_read"]),
    )
)
add_system_role(
    V2role(
        "organization_staleness_and_deletion_viewer",
        frozenset(["staleness_staleness_read"]),
    )
)
add_system_role(V2role("subscription_watch_administrator", frozenset(["subscriptions_all_all"])))
add_system_role(
    V2role(
        "subscriptions_user",
        frozenset(
            [
                "subscriptions_reports_read",
                "subscriptions_manifests_read",
                "subscriptions_organization_read",
                "subscriptions_products_read",
                "subscriptions_cloud_access_read",
            ]
        ),
    )
)
add_system_role(
    V2role(
        "tasks_administrator",
        frozenset(["tasks_all_all", "playbook_dispatcher_tasks_run_read"]),
    )
)
add_system_role(
    V2role(
        "vulnerability_administrator",
        frozenset(["vulnerability_all_all", "remediations_all_read", "remediations_all_write"]),
    )
)
add_system_role(
    V2role(
        "vulnerability_viewer",
        frozenset(
            [
                "vulnerability_vulnerability_results_read",
                "vulnerability_system_opt_out_read",
                "vulnerability_report_and_export_read",
                "vulnerability_advanced_report_read",
            ]
        ),
    )
)

skipped_apps = {"cost-management", "playbook-dispatcher", "approval", "catalog"}


def all_roles_v1_to_v2_mapping(v1_role: V1role) -> FrozenSet[V2rolebinding]:
    """Convert a V1 role to a set of V2 role bindings."""
    perm_groupings: Permissiongroupings = {}
    # Group V2 permissions by target
    for v1_perm in v1_role.permissions:
        if not is_for_enabled_app(v1_perm):
            continue
        v2_perm = v1_perm_to_v2_perm(v1_perm)
        if v1_perm.resourceDefs and len(v1_perm.resourceDefs) > 0:
            for resource_def in v1_perm.resourceDefs:
                resource_type = (
                    "workspace"
                    if v1_perm.app == "inventory"
                    else v1_attributefilter_resource_type_to_v2_resource_type(resource_def.resource_type)
                )
                # will assume workspaces exist already
                for resource_id in split_resourcedef_literal(resource_def):
                    if resource_type == "workspace":
                        if resource_id is None:
                            resource_id = "org_migration_root/ungrouped"
                        if v1_perm == "inventory_groups_read":
                            v1_perm = "workspace_read"
                        elif v1_perm == "inventory_groups_write":
                            v1_perm = "workspace_write"
                        elif v1_perm == "inventory_groups_all":
                            v1_perm = "workspace_all"
                    add_element(
                        perm_groupings,
                        V2boundresource(resource_type, resource_id),
                        v2_perm,
                    )
        else:
            add_element(
                perm_groupings,
                V2boundresource("workspace", "org_migration_root"),
                v2_perm,
            )
    # Project permission sets to system roles
    resource_roles = extract_system_roles(perm_groupings, v1_role)

    # Construct rolebindings
    v2_role_bindings = []
    v2_groups = v1groups_to_v2groups(v1_role.groups)
    for role, resources in resource_roles.items():
        for resource in resources:
            for v2_group in v2_groups:
                role_binding_id = str(uuid.uuid4())
                v2_role_binding = V2rolebinding(role_binding_id, role, frozenset({resource}), frozenset({v2_group}))
                v2_role_bindings.append(v2_role_binding)
    return frozenset(v2_role_bindings)


def convert_dispatcher_permission_to_v2(perm: V1permission):
    """Convert a V1 playbook dispatcher permission to a V2 permission."""
    if len(perm.resourceDefs) != 1:
        print(
            "Playbook dispatcher permission with unexpected number of resource definitions (should be 1): ",
            perm,
        )
    (resourceDef,) = perm.resourceDefs

    return f"playbook_dispatcher_{resourceDef.resource_id}_run_read"


candidate_system_roles = {}
custom_roles_created = 0


def extract_system_roles(perm_groupings, v1_role):
    """Extract system roles from a set of permissions."""
    resource_roles = {}
    for resource, permissions in perm_groupings.items():
        system_role = system_roles.get(frozenset(permissions))
        if system_role is not None:
            role = system_roles[frozenset(permissions)]
            add_element(resource_roles, role, resource)
        else:
            permset = set(permissions)
            granted = set()
            matched_roles = []

            for sysperms, sysrole in system_roles.items():
                if sysperms.issubset(permset) and not sysperms.issubset(
                    granted
                ):  # If all permissions on the role should be granted but not all of them have been, add it
                    matched_roles.append(sysrole)
                    granted |= sysperms

                if permset == granted:
                    break
            if permset == granted:
                for role in matched_roles:
                    add_element(resource_roles, role, resource)
            else:
                # Track leftovers and add a custom role
                leftovers = permset - granted
                print("No system role for: ")
                print(resource, leftovers, v1_role.id)
                print("\n")
                # Track possible missing system roles
                # Get applications with unmatched permissions
                apps = {}
                for perm in leftovers:
                    app = perm.split("_", 1)[0]  # Hack since we don't have the V1 data anymore by this point
                    if app not in apps:
                        apps[app] = []
                # Get original permissions granted on this resource grouped by application,
                # for applications with unmatched permissions
                for perm in permissions:
                    app = perm.split("_", 1)[0]  # Hack since we don't have the V1 data anymore by this point
                    if app in apps:
                        apps[app].append(perm)
                # Increment counts for each distinct set of permissions

                for app, perms in apps.items():
                    candidate = frozenset(perms)
                    if candidate in candidate_system_roles:
                        candidate_system_roles[candidate].add(v1_role.id)
                    else:
                        candidate_system_roles[candidate] = {v1_role.id}
                # Add a custom role
                add_element(resource_roles, V2role(str(uuid.uuid4()), frozenset(permissions)), resource)
                global custom_roles_created
                custom_roles_created += 1
    return resource_roles


def is_for_enabled_app(perm: V1permission):
    """Return true if the permission is for an app that is no longer in use."""
    return perm.app not in skipped_apps


def split_resourcedef_literal(resourceDef: V1resourcedef):
    """Split a resource definition into a list of resource IDs."""
    if resourceDef.op == "in":
        try:
            return json.loads(resourceDef.resource_id)  # Most are JSON arrays
        except json.JSONDecodeError:
            return resourceDef.resource_id.split(
                ","
            )  # If not JSON, assume comma-separated? Cost Management openshift assets are like this.
    else:
        return [resourceDef.resource_id]


def shared_system_role_replicated_role_bindings_v1_to_v2_mapping(v1_role: V1role) -> FrozenSet[V2rolebinding]:
    """Convert a V1 role to a set of V2 role bindings."""
    return all_roles_v1_to_v2_mapping(v1_role)


def v1groups_to_v2groups(v1groups: FrozenSet[V1group]):
    """Convert a set of V1 groups to a set of V2 groups."""
    return frozenset([V2group(v1group.id, v1group.users) for v1group in v1groups])


def v1_perm_to_v2_perm(v1_permission):
    """Convert a V1 permission to a V2 permission."""
    if v1_permission.app == "inventory" and v1_permission.resource == "groups":
        return cleanNameForV2SchemaCompatibility(f"workspace_{v1_permission.perm}")


def v1_attributefilter_resource_type_to_v2_resource_type(resourceType: str):  # Format is app.type
    """Convert a V1 resource type to a V2 resource type."""
    parts = resourceType.split(".", 1)
    app = cleanNameForV2SchemaCompatibility(parts[0])
    resource = cleanNameForV2SchemaCompatibility(parts[1])
    return f"{app}/{resource}"
