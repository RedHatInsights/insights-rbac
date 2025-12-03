#
# Copyright 2022 Red Hat, Inc.
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

"""Utilities for Internal RBAC use."""
import json
import logging
import uuid
from typing import Optional

import jsonschema
from django.conf import settings
from django.db import transaction
from django.urls import resolve
from internal.schemas import INVENTORY_INPUT_SCHEMAS, RELATION_INPUT_SCHEMAS
from jsonschema import validate
from management.models import BindingMapping, Role, Workspace
from management.relation_replicator.logging_replicator import stringify_spicedb_relationship
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import PartitionKey, ReplicationEvent, ReplicationEventType
from management.relation_replicator.relations_api_replicator import RelationsApiReplicator
from management.workspace.relation_api_dual_write_workspace_handler import RelationApiDualWriteWorkspaceHandler
from migration_tool.utils import create_relationship

from api.models import User


logger = logging.getLogger(__name__)


def build_internal_user(request, json_rh_auth):
    """Build user object for internal requests."""
    user = User()
    valid_identity_types = ["Associate", "X509"]
    try:
        identity_type = json_rh_auth["identity"]["type"]
        if identity_type not in valid_identity_types:
            logger.debug(
                f"User identity type is not valid: '{identity_type}'. Valid types are: {valid_identity_types}"
            )
            return None
        user.username = json_rh_auth["identity"].get("associate", {}).get("email", "system")
        user.admin = True
        user.org_id = resolve(request.path).kwargs.get("org_id")
        return user
    except KeyError:
        logger.debug(
            f"Identity object is missing 'identity.type' attribute. Valid options are: {valid_identity_types}"
        )
        return None


def delete_bindings(bindings):
    """
    Delete the provided bindings and replicate the deletion event.

    Args:
        bindings (QuerySet): A Django QuerySet of binding objects to be deleted.

    Returns:
        dict: A dictionary containing information about the deleted bindings, including:
            - mappings (list): A list of mappings for each binding.
            - role_ids (list): A list of role IDs for each binding.
            - resource_ids (list): A list of resource IDs for each binding.
            - resource_types (list): A list of resource type names for each binding.
            - relations (list): A list of tuples representing the relations to be removed.
    """
    replicator = OutboxReplicator()
    # Get org_id from first binding's role tenant
    org_id = str(bindings.first().role.tenant.org_id) if bindings.exists() else ""
    info = {
        "mappings": [binding.mappings for binding in bindings],
        "role_ids": [binding.role_id for binding in bindings],
        "resource_ids": [binding.resource_id for binding in bindings],
        "resource_types": [binding.resource_type_name for binding in bindings],
        "org_id": org_id,
    }
    if bindings:
        with transaction.atomic():
            relations_to_remove = []
            for binding in bindings:
                relations_to_remove.extend(binding.as_tuples())
            replicator.replicate(
                ReplicationEvent(
                    event_type=ReplicationEventType.DELETE_BINDING_MAPPINGS,
                    info=info,
                    partition_key=PartitionKey.byEnvironment(),
                    remove=relations_to_remove,
                ),
            )
            bindings.delete()
        info["relations"] = [stringify_spicedb_relationship(relation) for relation in relations_to_remove]
    return info


def read_tuples_from_kessel(resource_type: str, resource_id: str, relation: str, subject_type: str, subject_id: str):
    """
    Read tuples from Kessel Relations API.

    This is a convenience wrapper around RelationsApiReplicator.read_tuples()
    that uses the default "rbac" namespace.

    Args:
        resource_type: Type of the resource (e.g., "tenant", "workspace", "role_binding", "role")
        resource_id: ID of the resource
        relation: Relation to filter by (empty string for all relations)
        subject_type: Type of the subject to filter by
        subject_id: ID of the subject to filter by (empty string for all)

    Returns:
        list[dict]: List of tuple dictionaries from Kessel
    """
    replicator = RelationsApiReplicator()
    return replicator.read_tuples(
        resource_type=resource_type,
        resource_id=resource_id,
        relation=relation,
        subject_type=subject_type,
        subject_id=subject_id,
    )


def cleanup_tenant_orphaned_relationships(
    tenant,
    root_workspace,
    default_workspace,
    tenant_mapping,
    read_tuples_fn,
    dry_run: bool = False,
) -> dict:
    """
    Clean up orphaned role binding relationships for a tenant.

    This function:
    1. Queries Kessel for all role_bindings scoped to tenant/root/default workspace
    2. Excludes TenantMapping default access binding UUIDs
    3. Replicates DELETE for:
       - binding→role relationships
       - binding→group (subject) relationships
       - workspace/tenant→binding relationships (scope bindings)
    4. For custom V2 roles (not in system role UUIDs), also deletes role→permission tuples

    Args:
        tenant: The Tenant object to clean relationships for
        root_workspace: The root workspace for the tenant
        default_workspace: The default workspace for the tenant
        tenant_mapping: The TenantMapping for the tenant
        read_tuples_fn: Function to read tuples from Kessel, signature:
                        (resource_type: str, resource_id: str, relation: str,
                         subject_type: str = "", subject_id: str = "") -> list[dict]
        dry_run: If True, only report what would be deleted without making changes

    Returns:
        dict: Results including bindings found, relations to remove, etc.
    """
    # Get system role UUIDs (same for V1 and V2)
    system_role_uuids = set(str(u) for u in Role.objects.filter(system=True).values_list("uuid", flat=True))

    # Collect TenantMapping role_binding UUIDs to exclude (default access bindings)
    excluded_binding_uuids = {
        str(tenant_mapping.default_role_binding_uuid),
        str(tenant_mapping.default_admin_role_binding_uuid),
        str(tenant_mapping.root_scope_default_role_binding_uuid),
        str(tenant_mapping.root_scope_default_admin_role_binding_uuid),
        str(tenant_mapping.tenant_scope_default_role_binding_uuid),
        str(tenant_mapping.tenant_scope_default_admin_role_binding_uuid),
    }

    # Define scope resources to query
    scope_resources = [
        ("tenant", tenant.tenant_resource_id()),
        ("workspace", str(root_workspace.id)),
        ("workspace", str(default_workspace.id)),
    ]

    # Query Kessel for all role_bindings attached to scope resources
    # Track binding_id -> list of (resource_type, resource_id) for scope relationships
    bindings_to_clean = set()
    binding_scope_relations = {}  # binding_id -> [(resource_type, resource_id), ...]

    for resource_type, resource_id in scope_resources:
        # Query: resource → binding → role_binding:*
        binding_tuples = read_tuples_fn(resource_type, resource_id, "binding", "role_binding", "")
        for t in binding_tuples:
            binding_id = t.get("subject", {}).get("subject", {}).get("id")
            if binding_id:
                bindings_to_clean.add(binding_id)
                # Track the scope relationship for this binding
                if binding_id not in binding_scope_relations:
                    binding_scope_relations[binding_id] = []
                binding_scope_relations[binding_id].append((resource_type, resource_id))

    # Exclude TenantMapping default access bindings
    bindings_to_clean -= excluded_binding_uuids
    # Also remove excluded bindings from scope relations tracking
    for excluded_id in excluded_binding_uuids:
        binding_scope_relations.pop(excluded_id, None)

    logger.info(
        f"Found {len(bindings_to_clean)} bindings to clean for tenant {tenant.org_id} "
        f"(excluded {len(excluded_binding_uuids)} default access bindings)"
    )

    # Build relations to remove
    relations_to_remove = []
    custom_v2_roles_to_clean = set()

    for binding_id in bindings_to_clean:
        # Query: role_binding:<id> → role → role:*
        role_tuples = read_tuples_fn("role_binding", binding_id, "role", "role", "")
        for t in role_tuples:
            role_id = t.get("subject", {}).get("subject", {}).get("id")
            if role_id:
                # Create relationship for deletion
                relations_to_remove.append(
                    create_relationship(
                        ("rbac", "role_binding"),
                        binding_id,
                        ("rbac", "role"),
                        role_id,
                        "role",
                    )
                )
                # If this is a custom V2 role (not a system role), mark for permission cleanup
                if role_id not in system_role_uuids:
                    custom_v2_roles_to_clean.add(role_id)

        # Query: role_binding:<id> → subject → group:*#member
        group_tuples = read_tuples_fn("role_binding", binding_id, "subject", "group", "")
        for t in group_tuples:
            group_id = t.get("subject", {}).get("subject", {}).get("id")
            subject_relation = t.get("subject", {}).get("relation")
            if group_id:
                relations_to_remove.append(
                    create_relationship(
                        ("rbac", "role_binding"),
                        binding_id,
                        ("rbac", "group"),
                        group_id,
                        "subject",
                        subject_relation=subject_relation,
                    )
                )

        # Remove the scope binding relationships: workspace/tenant → binding → role_binding
        # These orphaned relationships exist when BindingMapping was deleted via cascade
        scope_relations = binding_scope_relations.get(binding_id, [])
        for resource_type, resource_id in scope_relations:
            relations_to_remove.append(
                create_relationship(
                    ("rbac", resource_type),
                    resource_id,
                    ("rbac", "role_binding"),
                    binding_id,
                    "binding",
                )
            )

    # For custom V2 roles, also delete role → permission → principal:* tuples
    for role_id in custom_v2_roles_to_clean:
        # Query: role:<id> → * → principal:*
        # We need to get all permission relations on this role
        permission_tuples = read_tuples_fn("role", role_id, "", "principal", "*")
        for t in permission_tuples:
            relation = t.get("relation")
            if relation:
                relations_to_remove.append(
                    create_relationship(
                        ("rbac", "role"),
                        role_id,
                        ("rbac", "principal"),
                        "*",
                        relation,
                    )
                )

    logger.info(
        f"Prepared {len(relations_to_remove)} relations to remove for tenant {tenant.org_id} "
        f"({len(custom_v2_roles_to_clean)} custom V2 roles to clean)"
    )

    result = {
        "org_id": tenant.org_id,
        "dry_run": dry_run,
        "bindings_found": len(bindings_to_clean),
        "bindings_cleaned": list(bindings_to_clean),
        "excluded_bindings": list(excluded_binding_uuids),
        "custom_v2_roles_cleaned": list(custom_v2_roles_to_clean),
        "relations_to_remove_count": len(relations_to_remove),
    }

    if not dry_run and relations_to_remove:
        replicator = OutboxReplicator()
        replicator.replicate(
            ReplicationEvent(
                event_type=ReplicationEventType.CLEANUP_ORPHAN_BINDINGS,
                info={
                    "org_id": tenant.org_id,
                    "bindings_cleaned": list(bindings_to_clean),
                    "custom_v2_roles_cleaned": list(custom_v2_roles_to_clean),
                },
                partition_key=PartitionKey.byEnvironment(),
                remove=relations_to_remove,
            )
        )
        result["relations_removed"] = [stringify_spicedb_relationship(rel) for rel in relations_to_remove]
    elif dry_run:
        result["relations_to_remove"] = [stringify_spicedb_relationship(rel) for rel in relations_to_remove]

    return result


def replicate_missing_binding_tuples(binding_ids: Optional[list[int]] = None) -> dict:
    """
    Replicate all tuples for specified bindings to fix missing relationships in Kessel.

    This fixes bindings created before REPLICATION_TO_RELATION_ENABLED=True that are missing
    base tuples (t_role and t_binding) in Kessel.

    Args:
        binding_ids (list[int], optional): List of binding IDs to fix. If None, fixes ALL bindings.

    Returns:
        dict: Results with bindings_checked, bindings_fixed, and tuples_added count.
    """
    logger = logging.getLogger(__name__)

    # Get bindings to fix
    if binding_ids:
        bindings_query = BindingMapping.objects.filter(id__in=binding_ids)
        logger.info(f"Fixing {len(binding_ids)} specific bindings: {binding_ids}")
    else:
        bindings_query = BindingMapping.objects.all()
        logger.warning(f"Fixing ALL bindings ({bindings_query.count()} total) - this may take a while")

    bindings_checked = 0
    bindings_fixed = 0
    total_tuples = 0

    # Process each binding in a separate transaction with locking
    for raw_binding in bindings_query.prefetch_related("role").iterator(chunk_size=2000):
        with transaction.atomic():
            # Custom roles must be locked, since other code that updates them locks only the role (and not the binding).
            if not raw_binding.role.system:
                locked_role = Role.objects.select_for_update().filter(pk=raw_binding.role.pk).first()

                if locked_role is None:
                    logger.warning(
                        f"Role vanished before its binding could be fixed: binding pk={raw_binding.pk!r}, "
                        f"role pk={raw_binding.role.pk!r}"
                    )

                    continue

            # Lock the binding to prevent concurrent modifications
            binding = BindingMapping.objects.select_for_update().filter(pk=raw_binding.pk).first()

            if binding is None:
                logger.warning(f"Binding vanished before it could be fixed: pk={raw_binding.pk!r}")
                continue

            bindings_checked += 1

            # Get ALL tuples for this binding (t_role, t_binding, and all subject tuples)
            # Kessel/SpiceDB handles duplicates gracefully, so it's safe to replicate existing tuples
            all_tuples = binding.as_tuples()

            # Replicate ALL tuples - any that already exist will be handled as duplicates
            replicator = OutboxReplicator()
            replicator.replicate(
                ReplicationEvent(
                    event_type=ReplicationEventType.REMIGRATE_ROLE_BINDING,
                    info={
                        "binding_id": binding.id,
                        "role_uuid": str(binding.role.uuid),
                        "org_id": str(binding.role.tenant.org_id),
                        "fix": "missing_binding_tuples",
                    },
                    partition_key=PartitionKey.byEnvironment(),
                    add=all_tuples,
                )
            )

            bindings_fixed += 1
            total_tuples += len(all_tuples)

        # Log progress for large batches (outside transaction)
        if bindings_checked % 100 == 0:
            logger.info(f"Progress: {bindings_checked} bindings processed, {total_tuples} tuples added")

    results = {
        "bindings_checked": bindings_checked,
        "bindings_fixed": bindings_fixed,
        "tuples_added": total_tuples,
    }

    logger.info(f"Completed: Fixed {bindings_fixed} bindings with {total_tuples} total tuples")

    return results


def clean_invalid_workspace_resource_definitions(dry_run: bool = False) -> dict:
    """
    Clean resource definitions with invalid workspace IDs and update bindings accordingly.

    This finds custom roles with resource definitions pointing to non-existent workspaces,
    removes invalid workspace IDs, and uses the dual write handler to update bindings.

    Args:
        dry_run (bool): If True, only report what would be changed without making changes.

    Returns:
        dict: Results with roles_checked, resource_definitions_fixed, and changes list.
    """
    logger = logging.getLogger(__name__)
    from management.role.relation_api_dual_write_handler import RelationApiDualWriteHandler
    from management.relation_replicator.relation_replicator import ReplicationEventType

    roles_checked = 0
    resource_defs_fixed = 0
    changes = []

    if dry_run:
        logger.info("DRY RUN MODE - No changes will be made")

    # Get all custom roles with resource definitions
    custom_roles_with_rds = Role.objects.filter(system=False, access__resourceDefinitions__isnull=False).distinct()

    for raw_role in custom_roles_with_rds.iterator():
        role_had_invalid_rds = False

        with transaction.atomic():
            # Lock the role to prevent concurrent modifications
            role = Role.objects.select_for_update().filter(pk=raw_role.pk).first()

            if role is None:
                logger.warning(f"Role vanished before it could be cleaned: pk={raw_role.pk!r}")
                continue

            roles_checked += 1

            dual_write = RelationApiDualWriteHandler(role, ReplicationEventType.FIX_RESOURCE_DEFINITIONS)
            dual_write.prepare_for_update()

            for access in role.access.all():
                permission = access.permission

                # Only check workspace-related resource definitions
                for rd in access.resourceDefinitions.all():
                    if not is_resource_a_workspace(
                        permission.application, permission.resource_type, rd.attributeFilter
                    ):
                        continue

                    # Get workspace IDs from resource definition
                    workspace_ids = get_workspace_ids_from_resource_definition(rd.attributeFilter)

                    # Check if the resource definition has None (for ungrouped workspace)
                    operation = rd.attributeFilter.get("operation")
                    original_value = rd.attributeFilter.get("value")
                    has_none_value = False

                    if operation == "in" and isinstance(original_value, list):
                        has_none_value = None in original_value
                    elif operation == "equal":
                        has_none_value = original_value is None

                    if not workspace_ids:
                        continue

                    # Check which workspaces exist in the role's tenant
                    valid_workspace_ids = set(
                        str(ws_id)
                        for ws_id in Workspace.objects.filter(id__in=workspace_ids, tenant=role.tenant).values_list(
                            "id", flat=True
                        )
                    )

                    invalid_workspace_ids = set(str(ws_id) for ws_id in workspace_ids) - valid_workspace_ids

                    if invalid_workspace_ids:
                        role_had_invalid_rds = True

                        # Calculate what the new value would be
                        operation_type = rd.attributeFilter.get("operation")
                        new_value: str | list | None
                        if operation_type == "equal":
                            # For "equal" operation, value should be a single string, None, or empty string
                            # Preserve None if it existed (for ungrouped workspace reference)
                            if has_none_value and not valid_workspace_ids:
                                new_value = None
                            else:
                                new_value = list(valid_workspace_ids)[0] if valid_workspace_ids else ""
                        else:
                            # For "in" operation, value should be a list
                            # Preserve None value if it existed (for ungrouped workspace reference)
                            new_value_list: list[str | None] = list(valid_workspace_ids) if valid_workspace_ids else []
                            if has_none_value:
                                new_value_list.append(None)
                            new_value = new_value_list

                        change_info = {
                            "role_uuid": str(role.uuid),
                            "role_name": role.name,
                            "permission": permission.permission,
                            "resource_definition_id": rd.id,
                            "operation": operation_type,
                            "original_value": original_value,
                            "new_value": new_value,
                            "invalid_workspaces": list(invalid_workspace_ids),
                            "valid_workspaces": list(valid_workspace_ids),
                            "preserved_none": has_none_value,
                        }

                        if dry_run:
                            logger.info(
                                f"[DRY RUN] Would update role '{role.name}' (uuid={role.uuid}), "
                                f"permission '{permission.permission}', RD #{rd.id}:\n"
                                f"  Original value: {original_value}\n"
                                f"  New value: {new_value}\n"
                                f"  Invalid workspace IDs removed: {list(invalid_workspace_ids)}\n"
                                f"  Valid workspace IDs kept: {list(valid_workspace_ids)}\n"
                                f"  None preserved: {has_none_value}"
                            )
                            change_info["action"] = "would_update"
                        else:
                            # Update resource definition to remove invalid workspace IDs
                            # Create new dict to ensure Django detects the change (JSONField mutation issue)
                            updated_filter = rd.attributeFilter.copy()
                            updated_filter["value"] = new_value

                            rd.attributeFilter = updated_filter
                            rd.save()
                            resource_defs_fixed += 1
                            change_info["action"] = "updated"

                            logger.info(
                                f"Updated role '{role.name}' (uuid={role.uuid}), "
                                f"permission '{permission.permission}', RD #{rd.id}: "
                                f"{original_value} -> {new_value}"
                            )

                        changes.append(change_info)

            # If we fixed any resource definitions, trigger dual write to update bindings
            if role_had_invalid_rds and not dry_run:
                dual_write.replicate_new_or_updated_role(role)  # Update bindings based on new RDs

    results = {
        "roles_checked": roles_checked,
        "resource_definitions_fixed": resource_defs_fixed,
        "changes": changes,
        "dry_run": dry_run,
    }

    if dry_run:
        logger.info(
            f"[DRY RUN] Would clean invalid workspace RDs: "
            f"{len(changes)} RDs would be fixed across {roles_checked} roles"
        )
    else:
        logger.info(f"Cleaned invalid workspace RDs: {resource_defs_fixed} RDs fixed for {len(changes)} permissions")

    return results


@transaction.atomic
def get_or_create_ungrouped_workspace(tenant: str) -> Workspace:
    """
    Retrieve the ungrouped workspace for the given tenant.

    Args:
        tenant (str): The tenant for which to retrieve the ungrouped workspace.
    Returns:
        Workspace: The ungrouped workspace object for the given tenant.
    """
    # fetch parent only once
    default_ws = Workspace.objects.get(tenant=tenant, type=Workspace.Types.DEFAULT)

    # single select_for_update + get_or_create
    workspace, created = Workspace.objects.select_for_update().get_or_create(
        tenant=tenant,
        type=Workspace.Types.UNGROUPED_HOSTS,
        defaults={"name": Workspace.SpecialNames.UNGROUPED_HOSTS, "parent": default_ws},
    )

    if created:
        RelationApiDualWriteWorkspaceHandler(
            workspace, ReplicationEventType.CREATE_WORKSPACE
        ).replicate_new_workspace()

    return workspace


def validate_relations_input(action, request_data) -> bool:
    """Check if request body provided to relations tool endpoints are valid."""
    validation_schema = RELATION_INPUT_SCHEMAS[action]
    try:
        validate(instance=request_data, schema=validation_schema)
        logger.info("JSON data is valid.")
        return True
    except jsonschema.exceptions.ValidationError as e:
        logger.info(f"JSON data is invalid: {e.message}")
        return False
    except Exception as e:
        logger.info(f"Exception occurred when validating JSON body: {e}")
        return False


def validate_inventory_input(action, request_data) -> bool:
    """Check if request body provided to inventory tool endpoints are valid."""
    validation_schema = INVENTORY_INPUT_SCHEMAS[action]
    try:
        validate(instance=request_data, schema=validation_schema)
        logger.info("JSON data is valid.")
        return True
    except jsonschema.exceptions.ValidationError as e:
        logger.info(f"JSON data is invalid: {e.message}")
        return False
    except Exception as e:
        logger.info(f"Exception occurred when validating JSON body: {e}")
        return False


def load_request_body(request) -> dict:
    """Decode request body from json into dict structure."""
    request_decoded = request.body.decode("utf-8")
    req_data = json.loads(request_decoded)
    return req_data


def is_resource_a_workspace(application: str, resource_type: str, attributeFilter: dict) -> bool:
    """Check if a given ResourceDefinition is a Workspace."""
    is_workspace_application = application == settings.WORKSPACE_APPLICATION_NAME
    is_workspace_resource_type = resource_type in settings.WORKSPACE_RESOURCE_TYPE
    is_workspace_group_filter = attributeFilter.get("key") == settings.WORKSPACE_ATTRIBUTE_FILTER
    return is_workspace_application and is_workspace_resource_type and is_workspace_group_filter


def get_workspace_ids_from_resource_definition(attributeFilter: dict) -> list[uuid.UUID]:
    """Get workspace id from a resource definition."""
    operation = attributeFilter.get("operation")
    ret = []
    if operation == "in":
        value = attributeFilter.get("value", [])
        ret.extend(uuid.UUID(val) for val in value if is_str_valid_uuid(val))
    elif operation == "equal":
        value = attributeFilter.get("value", "")
        if is_str_valid_uuid(value):
            ret.append(uuid.UUID(value))

    return ret


def is_str_valid_uuid(uuid_str: str) -> bool:
    """Check if a string can be converted to a valid UUID."""
    if not isinstance(uuid_str, str):
        return False
    if uuid_str is None or not uuid_str:
        return False
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        return False
