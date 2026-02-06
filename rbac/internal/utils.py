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
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Optional

import jsonschema
from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.urls import resolve
from internal.schemas import INVENTORY_INPUT_SCHEMAS, RELATION_INPUT_SCHEMAS
from jsonschema import validate
from management.group.platform import DefaultGroupNotAvailableError, GlobalPolicyIdService
from management.models import BindingMapping, Role, Workspace
from management.permission.scope_service import TenantScopeResources
from management.principal.proxy import PrincipalProxy
from management.relation_replicator.logging_replicator import LoggingReplicator, stringify_spicedb_relationship
from management.relation_replicator.noop_replicator import NoopReplicator
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import (
    PartitionKey,
    RelationReplicator,
    ReplicationEvent,
    ReplicationEventType,
)
from management.relation_replicator.relations_api_replicator import RelationsApiReplicator
from management.tenant_mapping.model import DefaultAccessType, TenantMapping
from management.tenant_service.relations import default_role_binding_tuples
from management.workspace.relation_api_dual_write_workspace_handler import RelationApiDualWriteWorkspaceHandler
from migration_tool.utils import create_relationship

from api.models import Tenant, User

logger = logging.getLogger(__name__)
PROXY = PrincipalProxy()


def get_replicator(write_relationships: str) -> RelationReplicator:
    """
    Get the appropriate replicator based on write_relationships setting.

    Args:
        write_relationships: How to handle replication.
            - "True" or "outbox": Create OutboxReplicator (replicate to outbox)
            - "logging": Create LoggingReplicator (log what would be replicated)
            - "False" or other: Create NoopReplicator (no replication)

    Returns:
        RelationReplicator instance
    """
    option = write_relationships.lower()

    if option == "true" or option == "outbox":
        return OutboxReplicator()

    if option == "logging":
        return LoggingReplicator()

    # "false"
    if option == "false":
        return NoopReplicator()

    raise ValueError(f"Invalid write_relationships option: {write_relationships}")


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


def iterate_tuples_from_kessel(
    resource_type: str, resource_id: str, relation: str, subject_type: str, subject_id: str
) -> Iterable[dict]:
    """
    Read tuples from Kessel Relations API while handling pagination.

    This is similar to read_tuples_from_kessel, except that it also returns subsequent pages from Kessel, and it does
    not necessarily return a list.
    """
    replicator = RelationsApiReplicator()

    continuation_token = None
    first = True

    while (continuation_token not in (None, "")) or first:
        batch = replicator.read_tuples(
            resource_type=resource_type,
            resource_id=resource_id,
            relation=relation,
            subject_type=subject_type,
            subject_id=subject_id,
            continuation_token=continuation_token,
        )

        if len(batch) == 0:
            return

        continuation_token = batch[-1]["pagination"]["continuation_token"]
        first = False

        yield from batch


def _build_workspace_graph(tenant) -> tuple[list, dict]:
    """
    Build workspace parent-child graph from DB workspace objects.

    This is a pure graph-building function that extracts the workspace hierarchy
    from the database. It's used by rebuild_tenant_workspace_relations for BFS traversal.

    Args:
        tenant: The Tenant object to get workspaces for

    Returns:
        tuple of:
        - root_workspace_ids: list of workspace IDs that have no parent (parent = tenant)
        - children_by_parent: dict mapping parent_id -> list of child workspace_ids
    """
    db_workspaces = list(Workspace.objects.filter(tenant=tenant).order_by("id"))
    children_by_parent: dict = {}
    root_workspace_ids: list = []

    for ws in db_workspaces:
        if ws.parent_id is None:
            root_workspace_ids.append(ws.id)
        else:
            children_by_parent.setdefault(ws.parent_id, []).append(ws.id)

    return root_workspace_ids, children_by_parent


@dataclass
class WorkspaceProcessResult:
    """Result of processing a single workspace in rebuild_tenant_workspace_relations."""

    checked: int = 0
    relations_added: int = 0
    relations_to_add_count: int = 0
    missing_parent: bool = False  # True if parent relation was missing


def _process_workspace_in_transaction(
    ws_id_uuid,
    expected_parent_type: str,
    expected_parent_id: str,
    tenant,
    read_tuples_fn,
    replicator,
    dry_run: bool,
) -> WorkspaceProcessResult:
    """
    Process a single workspace within a transaction.

    Locks parent (if workspace) and child, verifies parent hasn't changed,
    checks if parent relation exists in Kessel, and replicates if missing.

    Args:
        ws_id_uuid: The workspace UUID to process
        expected_parent_type: "tenant" or "workspace"
        expected_parent_id: The expected parent ID
        tenant: The Tenant object
        read_tuples_fn: Function to read tuples from Kessel
        replicator: The replicator to use for writing relations
        dry_run: If True, don't actually replicate

    Returns:
        WorkspaceProcessResult with counts and IDs
    """
    result = WorkspaceProcessResult()

    with transaction.atomic():
        # Lock parent first (if it's a workspace, not tenant)
        if expected_parent_type == "workspace":
            try:
                Workspace.objects.select_for_update().get(id=expected_parent_id)
            except Workspace.DoesNotExist:
                logger.warning(f"Parent workspace {expected_parent_id} no longer exists, skipping child {ws_id_uuid}")
                return result

        # Lock the child workspace
        try:
            ws = Workspace.objects.select_for_update().get(id=ws_id_uuid)
        except Workspace.DoesNotExist:
            logger.warning(f"Workspace {ws_id_uuid} no longer exists, skipping")
            return result

        result.checked = 1
        ws_id = str(ws.id)

        # Verify parent hasn't changed (in case of concurrent modification)
        actual_parent_id = str(ws.parent_id) if ws.parent_id else None
        if expected_parent_type == "tenant" and actual_parent_id is not None:
            logger.warning(f"Workspace {ws_id} parent changed from tenant to {actual_parent_id}, skipping")
            return result
        if expected_parent_type == "workspace" and actual_parent_id != expected_parent_id:
            logger.warning(
                f"Workspace {ws_id} parent changed from {expected_parent_id} to {actual_parent_id}, skipping"
            )
            return result

        # Check if parent relation exists in Kessel
        parent_tuples = read_tuples_fn("workspace", ws_id, "parent", expected_parent_type, expected_parent_id)
        if parent_tuples:
            return result

        # Missing parent relation
        result.missing_parent = True

        # Create the missing parent relation
        relation = create_relationship(
            ("rbac", "workspace"),
            ws_id,
            ("rbac", expected_parent_type),
            expected_parent_id,
            "parent",
        )

        if not dry_run:
            replicator.replicate(
                ReplicationEvent(
                    event_type=ReplicationEventType.MIGRATE_TENANT_GROUPS,
                    info={"tenant": tenant.org_id, "workspace": ws_id, "action": "rebuild_workspace_parent"},
                    partition_key=PartitionKey.byEnvironment(),
                    add=[relation],
                    remove=[],
                )
            )
            result.relations_added = 1
            logger.info(f"Added parent relation: workspace:{ws_id}#parent@{expected_parent_type}:{expected_parent_id}")
        else:
            result.relations_to_add_count = 1
            logger.info(f"DRY RUN: Would add: workspace:{ws_id}#parent@{expected_parent_type}:{expected_parent_id}")

    return result


def rebuild_tenant_workspace_relations(
    tenant,
    read_tuples_fn,
    replicator,
    dry_run: bool = False,
) -> dict:
    """
    Rebuild workspace parent relations for a tenant in Kessel.

    This function traverses all workspaces in the DB for a tenant and ensures
    their parent relations exist in Kessel. This is a prerequisite for
    cleanup_tenant_orphaned_relationships to work correctly.

    The hierarchy is: tenant -> root workspace -> default workspace -> other workspaces
    - Root workspace has parent = tenant
    - Other workspaces have parent = their parent workspace

    Uses BFS traversal starting from root workspace. For each workspace, locks the
    parent first, then locks the child, checks/replicates the parent relation,
    then moves to children. This minimizes lock contention.

    Args:
        tenant: The Tenant object to rebuild relations for
        read_tuples_fn: Function to read tuples from Kessel, signature:
                        (resource_type: str, resource_id: str, relation: str,
                         subject_type: str = "", subject_id: str = "") -> list[dict]
        replicator: The replicator to use for writing relations
        dry_run: If True, only report what would be added without making changes

    Returns:
        dict: Results including workspaces checked, relations added, etc.
    """
    tenant_resource_id = tenant.tenant_resource_id()

    workspaces_checked = 0
    relations_added = 0
    relations_to_add_count = 0
    workspaces_missing_parent_count = 0

    # Build workspace graph from DB
    root_workspace_ids, children_by_parent = _build_workspace_graph(tenant)

    # Build BFS queue starting from root workspaces
    queue = deque()
    for root_id in root_workspace_ids:
        queue.append((root_id, "tenant", tenant_resource_id))

    # BFS traversal - process each workspace in transaction
    while queue:
        ws_id_uuid, expected_parent_type, expected_parent_id = queue.popleft()

        # Process workspace in transaction (locks parent then child)
        result = _process_workspace_in_transaction(
            ws_id_uuid,
            expected_parent_type,
            expected_parent_id,
            tenant,
            read_tuples_fn,
            replicator,
            dry_run,
        )

        # Aggregate results
        workspaces_checked += result.checked
        relations_added += result.relations_added
        relations_to_add_count += result.relations_to_add_count
        if result.missing_parent:
            workspaces_missing_parent_count += 1

        # Add children to queue for BFS (outside transaction to release locks)
        if ws_id_uuid in children_by_parent:
            for child_id in children_by_parent[ws_id_uuid]:
                queue.append((child_id, "workspace", str(ws_id_uuid)))

    if dry_run and relations_to_add_count:
        logger.info(f"DRY RUN: Would add {relations_to_add_count} parent relations for tenant {tenant.org_id}")

    return {
        "org_id": tenant.org_id,
        "dry_run": dry_run,
        "workspaces_checked": workspaces_checked,
        "workspaces_missing_parent": workspaces_missing_parent_count,
        "relations_to_add": relations_to_add_count if dry_run else relations_added,
        "relations_added": relations_added,
    }


def replicate_missing_binding_tuples(tenant: Optional[Tenant] = None, binding_ids: Optional[list[int]] = None) -> dict:
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

    if (tenant is not None) and (binding_ids is not None):
        raise ValueError("At most one of a Tenant and a list of binding IDs must be provided.")

    # Get bindings to fix
    if binding_ids is not None:
        bindings_query = BindingMapping.objects.filter(id__in=binding_ids)
        logger.info(f"Fixing {len(binding_ids)} specific bindings: {binding_ids}")
    elif tenant is not None:
        # We do not need to lock anything here. We assume that replication is currently working correctly, so any
        # workspaces created after this instant will be correctly replicated.
        workspace_ids_to_fix = set(Workspace.objects.filter(tenant=tenant).values_list("id", flat=True))

        bindings_query = BindingMapping.objects.filter(
            Q(resource_type_namespace="rbac", resource_type_name="workspace", resource_id__in=workspace_ids_to_fix)
            | Q(resource_type_namespace="rbac", resource_type_name="tenant", resource_id=tenant.tenant_resource_id())
        )

        logger.info(f"Fixing {bindings_query.count()} bindings from tenant pk={tenant.pk!r}, org_id={tenant.org_id!r}")
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
    from management.role.v1.relation_api_dual_write_handler import RelationApiDualWriteHandler
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


def fix_admin_default_bindings(org_id: str) -> dict:
    """
    Fix missing admin default bindings for a tenant.

    Admin default bindings may be missing if the tenant was bootstrapped before
    the admin default group was seeded. This function re-replicates the admin
    default bindings for the tenant.

    This is safe to run even when replication is enabled because admin default
    bindings are NOT customizable (unlike platform default bindings).

    Args:
        org_id (str): Organization ID for the tenant to fix

    Returns:
        dict: Results with admin_bindings_replicated count or error
    """
    logger = logging.getLogger(__name__)

    try:
        tenant = Tenant.objects.get(org_id=org_id)
    except Tenant.DoesNotExist:
        return {"org_id": org_id, "error": f"Tenant {org_id} not found"}

    try:
        tenant_mapping = tenant.tenant_mapping
    except TenantMapping.DoesNotExist:
        return {"org_id": org_id, "error": "TenantMapping not found. Tenant may not be bootstrapped."}

    try:
        root_workspace = Workspace.objects.root(tenant=tenant)
        default_workspace = Workspace.objects.default(tenant=tenant)
    except Workspace.DoesNotExist as e:
        return {"org_id": org_id, "error": f"Missing root or default workspace: {str(e)}"}

    try:
        policy_service = GlobalPolicyIdService.shared()
        scope_resources = TenantScopeResources.for_models(
            tenant=tenant,
            default_workspace=default_workspace,
            root_workspace=root_workspace,
        )

        admin_bindings = default_role_binding_tuples(
            tenant_mapping=tenant_mapping,
            target_resources=scope_resources,
            access_type=DefaultAccessType.ADMIN,
            policy_service=policy_service,
        )

        if admin_bindings:
            replicator = OutboxReplicator()
            replicator.replicate(
                ReplicationEvent(
                    event_type=ReplicationEventType.BOOTSTRAP_TENANT,
                    info={
                        "org_id": org_id,
                        "admin_only": True,
                        "admin_bindings_count": len(admin_bindings),
                    },
                    partition_key=PartitionKey.byEnvironment(),
                    add=admin_bindings,
                )
            )
            return {"org_id": org_id, "admin_bindings_replicated": len(admin_bindings)}
        else:
            return {"org_id": org_id, "admin_bindings_replicated": 0}

    except DefaultGroupNotAvailableError:
        return {"org_id": org_id, "error": "Admin default group not available"}
    except Exception as e:
        logger.error(f"Error fixing admin default bindings for tenant {org_id}: {str(e)}", exc_info=True)
        return {"org_id": org_id, "error": str(e)}
