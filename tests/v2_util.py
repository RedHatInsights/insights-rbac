from typing import Callable, Optional

from api.models import Tenant
from management.models import Permission, Role
from management.relation_replicator.noop_replicator import NoopReplicator
from management.role.v2_model import SeededRoleV2
from management.tenant_service import V2TenantBootstrapService
from management.tenant_service.tenant_service import BootstrappedTenant
from migration_tool.in_memory_tuples import (
    resource,
    all_of,
    relation,
    resource_type,
    InMemoryTuples,
    InMemoryRelationReplicator,
)


def seed_v2_role_from_v1(role: Role) -> SeededRoleV2:
    if not role.system:
        raise ValueError("System role expected.")

    # TODO: Set up the platform-/admin-default parent/child relationships if necessary. This isn't done here yet
    #  because no code yet cares.

    v2_role, _ = SeededRoleV2.objects.update_or_create(
        tenant=role.tenant,
        uuid=role.uuid,
        v1_source=role,
        defaults=dict(
            name=role.name,
            description=role.description,
        ),
    )

    v2_role.permissions.set(Permission.objects.filter(accesses__role=role))

    return v2_role


def make_read_tuples_mock(tuples: InMemoryTuples) -> Callable[[str, str, str, str, str], list[dict]]:
    """Get a function with the signature of (read/iterate)_tuples_from_kessel that reads from an InMemoryTuples."""

    def read_tuples_fn(resource_type_name, resource_id, relation_name, subject_type_name, subject_id):
        """Mock function to read tuples from InMemoryTuples."""
        # Build a filter based on the provided parameters
        filters = [resource_type("rbac", resource_type_name)]

        if resource_id:
            filters.append(resource("rbac", resource_type_name, resource_id))

        if relation_name:
            filters.append(relation(relation_name))

        found_tuples = tuples.find_tuples(all_of(*filters))

        # Convert to dict format matching Kessel gRPC response
        # Format: {"tuple": {"resource": {...}, "relation": "...", "subject": {...}}, ...}
        result = []
        for t in found_tuples:
            # Filter by subject type and id if provided
            if subject_type_name and t.subject.subject.type.name != subject_type_name:
                continue
            if subject_id and t.subject.subject.id != subject_id:
                continue

            subject_dict = {
                "subject": {
                    "type": {
                        "namespace": t.subject.subject.type.namespace,
                        "name": t.subject.subject.type.name,
                    },
                    "id": t.subject.subject.id,
                },
            }
            if t.subject.relation is not None:
                subject_dict["relation"] = t.subject.relation

            result.append(
                {
                    "tuple": {
                        "resource": {
                            "type": {
                                "namespace": t.resource.type.namespace,
                                "name": t.resource.type.name,
                            },
                            "id": t.resource.id,
                        },
                        "relation": t.relation,
                        "subject": subject_dict,
                    },
                }
            )
        return result

    return read_tuples_fn


def bootstrap_tenant_for_v2_test(tenant: Tenant, tuples: Optional[InMemoryTuples] = None) -> BootstrappedTenant:
    """
    Bootstrap a tenant for V2 testing.

    Relation writes are sent to tuples, if provided, and are otherwise discarded.
    """
    replicator = InMemoryRelationReplicator(tuples) if tuples is not None else NoopReplicator()
    return V2TenantBootstrapService(replicator=replicator).bootstrap_tenant(tenant, force=True)
