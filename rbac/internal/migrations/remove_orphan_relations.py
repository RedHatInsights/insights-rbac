#
# Copyright 2025 Red Hat, Inc.
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
import dataclasses
import itertools
import logging
from collections.abc import Callable, Iterable

from api.models import Tenant
from django.db import transaction
from internal.utils import read_tuples_from_kessel
from management.tenant_mapping.model import TenantMapping
from management.models import Group, Role, Workspace
from management.relation_replicator.logging_replicator import stringify_spicedb_relationship
from management.relation_replicator.outbox_replicator import OutboxReplicator
from management.relation_replicator.relation_replicator import ReplicationEvent, ReplicationEventType, PartitionKey
from management.tenant_service.v2 import lock_tenant_for_bootstrap, TenantBootstrapLock
from migration_tool.in_memory_tuples import RelationTuple
from migration_tool.migrate_binding_scope import migrate_all_role_bindings
from migration_tool.models import V2boundresource
from migration_tool.utils import create_relationship
from kessel.relations.v1beta1.common_pb2 import Relationship

logger = logging.getLogger(__name__)


type _CommitRemoval = Callable[[Iterable[Relationship | RelationTuple]], None]


def _as_relation_tuple(relation: Relationship | RelationTuple) -> RelationTuple:
    """Convert a Relationship or RelationTuple to a RelationTuple."""
    if isinstance(relation, RelationTuple):
        return relation

    if isinstance(relation, Relationship):
        return RelationTuple.from_message(relation)

    raise TypeError(f"Expected Relationship or RelationTuple, but got: {relation!r}")


def _as_relationship(relation: Relationship | RelationTuple) -> Relationship:
    """Convert a Relationship or RelationTuple to a Relationship."""
    if isinstance(relation, Relationship):
        return relation

    if isinstance(relation, RelationTuple):
        return relation.as_message()

    raise TypeError(f"Expected Relationship or RelationTuple, but got: {relation!r}")


class _RemoteBindingState:
    _relations: set[RelationTuple]
    _custom_role_ids: set[str]

    def __init__(self):
        self._relations = set()
        self._custom_role_ids = set()

    @staticmethod
    def _check_str_id(value):
        if not isinstance(value, str):
            raise TypeError(f"Expected ID to be a string, but got: {value!r}")

    def add_relations(self, relations: Iterable[Relationship | RelationTuple]):
        self._relations.update(_as_relation_tuple(r) for r in relations)

    def add_custom_role(self, custom_role_id: str):
        self._check_str_id(custom_role_id)
        self._custom_role_ids.add(custom_role_id)

    def relations(self) -> set[RelationTuple]:
        return set(self._relations)

    def custom_role_ids(self) -> set[str]:
        return set(self._custom_role_ids)


def _collect_remote_relations_for_binding(
    binding_id: str,
    scope_relations: list[tuple[str, str]],
    read_tuples_fn,
    system_role_uuids: set[str],
) -> _RemoteBindingState:
    """
    Collect all relations to remove for a single binding, including custom role permissions.

    Args:
        binding_id: The role_binding UUID to clean
        scope_relations: List of (resource_type, resource_id) tuples for scope bindings
        read_tuples_fn: Function to read tuples from Kessel
        system_role_uuids: Set of system role UUIDs to exclude from custom role cleanup

    Returns:
        _RemoteBindingState for the binding
    """
    result = _RemoteBindingState()

    # Query: role_binding:<id> → role → role:*
    role_tuples = read_tuples_fn("role_binding", binding_id, "role", "role", "")
    for t in role_tuples:
        # Response format: {"tuple": {..., "subject": {"subject": {"id": "..."}}}, ...}
        role_id = t.get("tuple", {}).get("subject", {}).get("subject", {}).get("id")
        if role_id:
            result.add_relations(
                [
                    create_relationship(
                        ("rbac", "role_binding"),
                        binding_id,
                        ("rbac", "role"),
                        role_id,
                        "role",
                    )
                ]
            )

            # If this is a custom V2 role (not a system role), collect permission relations inline
            if role_id not in system_role_uuids:
                result.add_custom_role(role_id)

    # Query: role_binding:<id> → subject → group:*#member
    group_tuples = read_tuples_fn("role_binding", binding_id, "subject", "group", "")
    for t in group_tuples:
        # Response format: {"tuple": {..., "subject": {"subject": {"id": "..."}, "relation": "..."}}, ...}
        group_id = t.get("tuple", {}).get("subject", {}).get("subject", {}).get("id")
        subject_relation = t.get("tuple", {}).get("subject", {}).get("relation")
        if group_id:
            result.add_relations(
                [
                    create_relationship(
                        ("rbac", "role_binding"),
                        binding_id,
                        ("rbac", "group"),
                        group_id,
                        "subject",
                        subject_relation=subject_relation,
                    )
                ]
            )

    # Remove the scope binding relationships: workspace/tenant → binding → role_binding
    for resource_type, resource_id in scope_relations:
        result.add_relations(
            [
                create_relationship(
                    ("rbac", resource_type),
                    resource_id,
                    ("rbac", "role_binding"),
                    binding_id,
                    "binding",
                )
            ]
        )

    return result


def _collect_custom_role_permission_relations(role_id: str, read_tuples_fn) -> list[Relationship]:
    """
    Collect permission relations to remove for a custom V2 role.

    Args:
        role_id: The role UUID to clean permissions for
        read_tuples_fn: Function to read tuples from Kessel

    Returns:
        list: Relations to remove for this role's permissions
    """
    relations_to_remove = []
    permission_tuples = read_tuples_fn("role", role_id, "", "principal", "*")
    for t in permission_tuples:
        # Response format: {"tuple": {"relation": "...", ...}, ...}
        relation = t.get("tuple", {}).get("relation")
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
    return relations_to_remove


@dataclasses.dataclass
class _RemoveRoleBindingsResult:
    ordinary_bindings_removed_count: int
    default_access_bindings_removed_count: int
    custom_roles_removed_count: int


def _remove_all_role_bindings(
    *,
    tenant: Tenant,
    resource_type: str,
    resource_id: str,
    read_tuples_fn,
    commit_removal: _CommitRemoval,
    system_role_uuids: set[str],
) -> _RemoveRoleBindingsResult:
    """
    Find and remove all bindings attached to a resource (tenant or workspace).

    For each binding found:
    - Collects binding->role, binding->group, and scope->binding relations to remove
    - Collects custom V2 role permission relations inline

    Special handling for built-in bindings (from TenantMapping):
    - If tenant has NO custom default group: skip built-in bindings entirely
    - If tenant HAS custom default group: only remove scope binding (resource->binding),
      don't do normal cleanup (preserve binding->role, binding->group relationships)

    Args:
        tenant: The tenant
        resource_type: "tenant" or "workspace"
        resource_id: The resource ID
        read_tuples_fn: Function to read tuples from Kessel
        system_role_uuids: Set of system role UUIDs to exclude from custom role cleanup

    Returns: _RemoveRoleBindingsResults indicating what was done
    """
    scope_relations = [(resource_type, resource_id)]
    custom_role_ids: set[str] = set()

    bindings_cleaned_count = 0
    builtin_scope_cleaned_count = 0

    # Here, we will remove *all* role bindings for the tenant. We will recreate them all later.

    binding_tuples = read_tuples_fn(resource_type, resource_id, "binding", "role_binding", "")

    for batch in itertools.batched(binding_tuples, 100):
        binding_ids: set[str] = {
            b
            for b in (t.get("tuple", {}).get("subject", {}).get("subject", {}).get("id") for t in batch)
            if (b is not None)
        }

        lookup_result_by_binding = {
            b: _collect_remote_relations_for_binding(
                binding_id=b,
                scope_relations=scope_relations,
                read_tuples_fn=read_tuples_fn,
                system_role_uuids=system_role_uuids,
            )
            for b in binding_ids
        }

        with transaction.atomic():
            to_remove: list[RelationTuple | Relationship] = []

            bootstrap_lock: TenantBootstrapLock = lock_tenant_for_bootstrap(tenant)
            builtin_binding_ids: set[str] = bootstrap_lock.tenant_mapping.role_binding_ids()

            for binding_id in binding_ids:
                # Handle built-in bindings specially.
                if binding_id in builtin_binding_ids:
                    # If there is a custom default group: remove only the resource->binding relation.
                    # If there is not a custom default group, leave the binding untouched.
                    if bootstrap_lock.custom_default_group is not None:
                        to_remove.extend(
                            create_relationship(
                                ("rbac", resource_type),
                                resource_id,
                                ("rbac", "role_binding"),
                                binding_id,
                                "binding",
                            )
                        )

                        builtin_scope_cleaned_count += 1
                else:
                    logger.debug(f"Processing binding {binding_id} on {resource_type}:{resource_id}")

                    lookup_result = lookup_result_by_binding[binding_id]

                    to_remove.extend(lookup_result.relations())
                    custom_role_ids.update(lookup_result.custom_role_ids())

                    bindings_cleaned_count += 1

            commit_removal(to_remove)

    with transaction.atomic():
        to_remove = []

        for role_id in custom_role_ids:
            to_remove.extend(_collect_custom_role_permission_relations(role_id, read_tuples_fn))

        commit_removal(to_remove)

    return _RemoveRoleBindingsResult(
        ordinary_bindings_removed_count=bindings_cleaned_count,
        default_access_bindings_removed_count=builtin_scope_cleaned_count,
        custom_roles_removed_count=len(custom_role_ids),
    )


class _RemoteWorkspaceData:
    _parents_by_workspace: dict[str, set[V2boundresource]]

    def __init__(self):
        self._parents_by_workspace = {}

    @classmethod
    def _check_workspace_id(cls, workspace_id):
        if not isinstance(workspace_id, str):
            raise TypeError(f"Expected workspace ID to be a string, but got: {workspace_id!r}")

    def add_workspace(self, *, workspace_id: str, parent_resource: V2boundresource):
        self._check_workspace_id(workspace_id)
        self._parents_by_workspace.setdefault(workspace_id, set()).add(parent_resource)

    def has_workspace(self, workspace_id: str) -> bool:
        self._check_workspace_id(workspace_id)
        return workspace_id in self._parents_by_workspace

    def parents_for(self, workspace_id: str) -> set[V2boundresource]:
        self._check_workspace_id(workspace_id)
        return self._parents_by_workspace.get(workspace_id, set())

    def workspace_ids(self) -> set[str]:
        return set(self._parents_by_workspace.keys())


def _workspace_parent_relationship(workspace_id: str, parent: V2boundresource) -> Relationship:
    return create_relationship(
        resource_name=("rbac", "workspace"),
        resource_id=workspace_id,
        relation="parent",
        subject_name=parent.resource_type,
        subject_id=parent.resource_id,
    )


def _collect_remote_workspaces(tenant_resource_id: str, read_tuples_fn) -> _RemoteWorkspaceData:
    """
    Discover all workspaces under a tenant in Kessel.

    The hierarchy is: tenant -> root workspace -> default workspace -> other workspaces
    Each workspace has a `parent` relation pointing to its parent (tenant or workspace).

    Args:
        tenant_resource_id: The tenant resource ID to search from
        read_tuples_fn: Function to read tuples from Kessel

    Returns:
        dict: Mapping of workspace_id -> (parent_type, parent_id) for all workspaces found
    """
    workspace_data = _RemoteWorkspaceData()
    stack = []

    def add_seen_workspace(workspace_id: str, parent_resource: V2boundresource):
        # Enqueue this workspace for further searching, but ensure that we don't end up in a loop.
        if not workspace_data.has_workspace(workspace_id):
            stack.append(ws_id)

        workspace_data.add_workspace(workspace_id=ws_id, parent_resource=parent_resource)

    # Find root workspaces (workspace -> parent -> tenant)
    # Query with empty resource_id to find all workspaces with this tenant as parent
    root_tuples = read_tuples_fn("workspace", "", "parent", "tenant", tenant_resource_id)

    for t in root_tuples:
        # The workspace ID is in the resource part of the tuple response
        # Response format: {"tuple": {"resource": {"type": {...}, "id": "..."}, ...}, ...}
        ws_id = t.get("tuple", {}).get("resource", {}).get("id")

        if not ws_id:
            continue

        add_seen_workspace(ws_id, V2boundresource(("rbac", "tenant"), tenant_resource_id))

    # DFS to find child workspaces
    while stack:
        parent_ws_id = stack.pop()  # LIFO for DFS

        # Find workspaces where parent is this workspace
        child_tuples = read_tuples_fn("workspace", "", "parent", "workspace", parent_ws_id)

        for t in child_tuples:
            ws_id = t.get("tuple", {}).get("resource", {}).get("id")

            if not ws_id:
                continue

            add_seen_workspace(ws_id, V2boundresource(("rbac", "workspace"), parent_ws_id))

    return workspace_data


def _remove_orphaned_workspace_parent_relations(
    tenant: Tenant, workspace_data: _RemoteWorkspaceData, commit_removal: _CommitRemoval
) -> int:
    """Removes any parent relations for workspaces that no longer exist locally, then returns the number removed."""
    remote_ids = workspace_data.workspace_ids()

    # We do not need to lock workspaces locally while doing this. Workspace IDs are always random UUIDs, so there being
    # a *new* workspace with an ID we are interested in created between the time we check and the time we commit the
    # removals is virtually impossible.
    #
    # There is also no issue if a workspace has been locally deleted but the deletion has not yet been replicated.
    # It can't be recreated (for the reasons above), and redundantly deleting the relation will have no effect.
    existing_local_ids = set(Workspace.objects.filter(tenant=tenant, id__in=remote_ids).values_list("id", flat=True))

    orphaned_ids = remote_ids - existing_local_ids
    logger.info(
        f"Found {len(orphaned_ids)} orphaned workspace IDs for tenant (org_id={tenant.org_id!r}): {orphaned_ids}"
    )

    incorrect_relations = [
        _workspace_parent_relationship(workspace_id, parent)
        for workspace_id in orphaned_ids
        for parent in workspace_data.parents_for(workspace_id)
    ]

    commit_removal(incorrect_relations)

    return len(incorrect_relations)


def _remove_incorrect_workspace_parent_relations(
    tenant: Tenant, workspace_data: _RemoteWorkspaceData, commit_removal: _CommitRemoval
) -> int:
    remote_ids = workspace_data.workspace_ids()
    tenant_resource = V2boundresource.for_model(tenant)

    removed_count = 0

    for raw_workspaces in itertools.batched(Workspace.objects.filter(id__in=remote_ids).iterator(), 100):
        to_remove = []

        with transaction.atomic():
            # We need to lock the workspaces because their parents could change while we're working.
            workspaces = list(Workspace.objects.filter(pk__in=[w.pk for w in raw_workspaces]).select_for_update())

            for workspace in workspaces:
                workspace_id = str(workspace.id)

                remote_parents = workspace_data.parents_for(workspace_id)

                expected_parents = {
                    (
                        V2boundresource.for_workspace_id(str(workspace.parent_id))
                        if workspace.parent_id is not None
                        else tenant_resource
                    )
                }

                excess_parents = remote_parents - expected_parents

                for excess_parent in excess_parents:
                    to_remove.append(_workspace_parent_relationship(workspace_id, excess_parent))

            logger.info(f"Removing {len(to_remove)} incorrect workspace parent relationships.")
            commit_removal(to_remove)

            removed_count += len(to_remove)

    return removed_count


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
    1. Checks if tenant has a custom default group (platform_default or admin_default)
    2. Uses DFS to discover all workspaces from Kessel starting from tenant
       (tenant -> root workspace -> default workspace -> other workspaces)
    3. Identifies orphaned workspaces (in Kessel but not in DB)
    4. Identifies workspaces with stale parent (parent in Kessel differs from DB)
    5. For each scope resource (tenant + all discovered workspaces), finds bindings
    6. Handles built-in bindings (from TenantMapping) specially:
       - If NO custom default group: skip built-in bindings entirely
       - If HAS custom default group: only remove scope binding (resource→binding),
         preserve binding→role and binding→group relationships
    7. For non-built-in bindings, replicates DELETE for:
       - binding→role relationships
       - binding→group (subject) relationships
       - workspace/tenant→binding relationships (scope bindings)
       - orphaned workspace→parent relationships
       - stale workspace→parent relationships (parent mismatch between Kessel and DB)
    8. For custom V2 roles (not in system role UUIDs), also deletes role→permission tuples

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
    replicator = OutboxReplicator()
    removed_count = 0

    # Process bindings and collect relations to remove
    # Counters for results
    bindings_cleaned_count = 0
    builtin_scope_cleaned_count = 0
    custom_roles_count = 0

    def commit_removal(relations: Iterable[Relationship | RelationTuple]):
        nonlocal removed_count

        converted_relations = [_as_relationship(r) for r in relations]

        if not converted_relations:
            return

        logger.info(f"Tenant {tenant.org_id} - relationships to remove:")

        for r in converted_relations:
            logger.info(f"  Removing: {stringify_spicedb_relationship(r)}")

        if not dry_run:
            replicator.replicate(
                ReplicationEvent(
                    event_type=ReplicationEventType.CLEANUP_ORPHAN_BINDINGS,
                    info={
                        "org_id": tenant.org_id,
                    },
                    partition_key=PartitionKey.byEnvironment(),
                    remove=converted_relations,
                )
            )

        removed_count += len(converted_relations)

    def do_remove_role_bindings(resource_type: str, resource_id: str):
        nonlocal bindings_cleaned_count, builtin_scope_cleaned_count, custom_roles_count

        result = _remove_all_role_bindings(
            tenant=tenant,
            resource_type=resource_type,
            resource_id=resource_id,
            read_tuples_fn=read_tuples_fn,
            system_role_uuids=system_role_uuids,
            commit_removal=commit_removal,
        )

        bindings_cleaned_count += result.ordinary_bindings_removed_count
        builtin_scope_cleaned_count += result.default_access_bindings_removed_count
        custom_roles_count += result.custom_roles_removed_count

    # Get system role UUIDs (same for V1 and V2)
    system_role_uuids = set(str(u) for u in Role.objects.filter(system=True).values_list("uuid", flat=True))

    kessel_workspace_data = _collect_remote_workspaces(tenant.tenant_resource_id(), read_tuples_fn)
    workspace_ids_in_kessel = set(kessel_workspace_data.workspace_ids())

    # Remove all the role bindings. We will add them back later (in cleanup_tenant_orphan_bindings).

    do_remove_role_bindings("tenant", tenant.tenant_resource_id())

    for ws_id in workspace_ids_in_kessel:
        do_remove_role_bindings("workspace", ws_id)

    logger.info(
        f"Tenant {tenant.org_id} cleanup summary: "
        f"bindings={bindings_cleaned_count}, builtin_scope={builtin_scope_cleaned_count}, "
        f"custom_roles={custom_roles_count}, workspaces={len(workspace_ids_in_kessel)}, "
    )

    # Remove parent relations last so that if another step fails then we are still able to find all the workspaces
    # that need to be processed later.

    orphaned_workspace_parent_count = _remove_orphaned_workspace_parent_relations(
        tenant=tenant,
        workspace_data=kessel_workspace_data,
        commit_removal=commit_removal,
    )

    incorrect_workspace_parent_count = _remove_incorrect_workspace_parent_relations(
        tenant=tenant,
        workspace_data=kessel_workspace_data,
        commit_removal=commit_removal,
    )

    # Return counts only
    return {
        "org_id": tenant.org_id,
        "dry_run": dry_run,
        "bindings_cleaned_count": bindings_cleaned_count,
        "builtin_bindings_scope_cleaned_count": builtin_scope_cleaned_count,
        "custom_v2_roles_cleaned_count": custom_roles_count,
        "workspaces_discovered_count": len(workspace_ids_in_kessel),
        "orphaned_workspace_relations_cleaned_count": orphaned_workspace_parent_count,
        "stale_parent_workspace_relations_cleaned_count": incorrect_workspace_parent_count,
        "relations_to_remove_count": removed_count,
    }


def cleanup_tenant_orphan_bindings(org_id: str, dry_run: bool = False, *, read_tuples_fn=None) -> dict:
    """
    Clean up orphaned role binding relationships for a tenant and run migration.

    This function:
    1. Validates tenant, TenantMapping, and workspaces exist
    2. Uses DFS to discover all workspaces from Kessel
    3. Identifies orphaned/stale workspace relationships
    4. Cleans orphaned binding relationships
    5. Runs migrate_all_role_bindings() to recreate correct state (if not dry_run)

    Args:
        org_id (str): Organization ID for the tenant to clean up
        dry_run (bool): If True, only report counts without making changes
        read_tuples_fn: Function to read tuples from Kessel (same signature as read_tuples_from_kessel)

    Returns:
        dict: Results with cleanup counts and migration results, or error details
    """
    logger.info(f"Cleaning orphaned relationships for tenant {org_id} (dry_run={dry_run})")

    # Get tenant
    try:
        tenant = Tenant.objects.get(org_id=org_id)
    except Tenant.DoesNotExist:
        logger.error(f"Tenant {org_id} not found")
        return {"error": f"Tenant {org_id} not found"}

    # Get TenantMapping
    try:
        tenant_mapping = tenant.tenant_mapping
    except TenantMapping.DoesNotExist:
        logger.error(f"No TenantMapping found for tenant {org_id}")
        return {"error": f"No TenantMapping found for tenant {org_id}. Tenant may not be bootstrapped."}

    # Get root and default workspaces
    try:
        root_workspace = Workspace.objects.root(tenant=tenant)
        default_workspace = Workspace.objects.default(tenant=tenant)
    except Workspace.DoesNotExist as e:
        logger.error(f"Missing root or default workspace for tenant {org_id}: {str(e)}")
        return {"error": f"Missing root or default workspace for tenant {org_id}: {str(e)}"}

    try:
        # Clean orphaned relationships
        cleanup_result = cleanup_tenant_orphaned_relationships(
            tenant=tenant,
            root_workspace=root_workspace,
            default_workspace=default_workspace,
            tenant_mapping=tenant_mapping,
            read_tuples_fn=(read_tuples_fn if read_tuples_fn is not None else read_tuples_from_kessel),
            dry_run=dry_run,
        )

        # Run migration if not dry_run
        migration_result = None
        if not dry_run:
            logger.info(f"Running migrate_all_role_bindings for tenant {org_id}")
            checked, migrated = migrate_all_role_bindings(tenant=tenant)
            migration_result = {
                "items_checked": checked,
                "items_migrated": migrated,
            }

        result = {
            "cleanup": cleanup_result,
            "migration": migration_result,
        }
        logger.info(f"Cleanup completed for tenant {org_id}")
        return result

    except Exception as e:
        logger.error(f"Error during cleanup for tenant {org_id}: {str(e)}", exc_info=True)
        return {"error": f"Error during cleanup: {str(e)}"}
