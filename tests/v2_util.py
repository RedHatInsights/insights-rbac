from typing import Optional
from unittest import TestCase

from management.group.platform import GlobalPolicyIdService, DefaultGroupNotAvailableError
from management.models import BindingMapping, CustomRoleV2, Permission, Role, RoleBinding, RoleV2
from management.permission.scope_service import Scope
from management.role.platform import platform_v2_role_uuid_for
from management.role.model import SeededRoleV2
from management.tenant_mapping.model import DefaultAccessType
from migration_tool.in_memory_tuples import (
    resource,
    all_of,
    relation,
    subject_type,
    subject,
    resource_type,
    InMemoryTuples,
)


def _v2_permissions_for(role: RoleV2) -> set[str]:
    return set(p.v2_string() for p in role.permissions.all())


def _assert_role_mappings_consistent(test: TestCase, role: CustomRoleV2, mappings: list[BindingMapping]):
    expected_permissions = _v2_permissions_for(role)

    test.assertGreater(len(mappings), 0, "Expected V2 role to be used in at least one BindingMapping.")

    for binding_mapping in mappings:
        test.assertFalse(binding_mapping.mappings["role"]["is_system"])

        test.assertEqual(
            expected_permissions,
            set(binding_mapping.mappings["role"]["permissions"]),
            f"Mismatched permissions between RoleV2 {role.uuid} and BindingMapping {binding_mapping.id} "
            f"({binding_mapping.mappings["id"]})",
        )


def _assert_role_tuples_consistent(test: TestCase, tuples: InMemoryTuples, role: RoleV2):
    expected_permissions = _v2_permissions_for(role)

    tuple_permissions = set(
        t.relation
        for t in tuples.find_tuples(
            all_of(
                resource("rbac", "role", str(role.uuid)),
                subject("rbac", "principal", "*"),
            )
        )
    )

    test.assertEqual(
        expected_permissions,
        tuple_permissions,
        f"Database and relations permissions do not match for role {role.uuid}",
    )


def _assert_binding_tuples_consistent(test: TestCase, tuples: InMemoryTuples, binding: RoleBinding):
    resource_predicate = resource("rbac", "role_binding", str(binding.uuid))

    role_tuples = tuples.find_tuples(
        all_of(
            resource_predicate,
            relation("role"),
            subject_type("rbac", "role"),
        )
    )

    test.assertEqual(1, len(role_tuples))
    test.assertEqual(str(binding.role.uuid), role_tuples.only.subject_id)

    resource_tuples = tuples.find_tuples(
        all_of(
            relation("binding"),
            subject(
                "rbac",
                "role_binding",
                str(binding.uuid),
            ),
        )
    )

    test.assertEqual(1, len(resource_tuples))
    test.assertEqual(binding.resource_type, resource_tuples.only.resource_type_name)
    test.assertEqual(binding.resource_id, resource_tuples.only.resource_id)

    db_groups = set(str(g.uuid) for g in binding.bound_groups())

    tuple_groups = set(
        t.subject_id
        for t in tuples.find_tuples(
            all_of(
                resource_predicate,
                relation("subject"),
                subject_type("rbac", "group", "member"),
            )
        )
    )

    test.assertEqual(
        db_groups,
        tuple_groups,
        f"Database and relations groups do not match for role binding {binding.uuid} "
        f"for role ({binding.role.uuid})",
    )

    db_principals = set(p.principal_resource_id() for p in binding.bound_principals())
    test.assertNotIn(None, db_principals)

    tuple_principals = set(
        t.subject_id
        for t in tuples.find_tuples(
            all_of(
                resource_predicate,
                relation("subject"),
                subject_type("rbac", "principal"),
            )
        )
    )

    test.assertCountEqual(
        db_principals,
        tuple_principals,
        f"Database and relations principals do not match for role binding {binding.uuid} "
        f"for role ({binding.role.uuid})",
    )


def _assert_binding_mapping_consistent(test: TestCase, binding: RoleBinding, mapping: BindingMapping):
    test.assertEqual(str(binding.uuid), mapping.mappings["id"])
    test.assertEqual(binding.role.v1_source, mapping.role)
    test.assertEqual(binding.resource_type, mapping.resource_type_name)
    test.assertEqual(binding.resource_id, mapping.resource_id)
    test.assertEqual(str(binding.role.uuid), mapping.mappings["role"]["id"])

    v1_groups = set(mapping.mappings["groups"])
    v2_groups = set(str(g.uuid) for g in binding.bound_groups())

    test.assertEqual(v1_groups, v2_groups)

    v1_entries = mapping.mappings["users"].items()
    v2_entries = [(e.source, e.principal.user_id) for e in binding.principal_entries.all()]

    test.assertCountEqual(v1_entries, v2_entries)


def _assert_v2_names(test: TestCase, v1_role: Role):
    v2_roles = list(CustomRoleV2.objects.filter(v1_source=v1_role))

    test.assertCountEqual(
        [r.name for r in v2_roles],
        [f"{v1_role.display_name} ({i + 1})" for i in range(len(v2_roles))],
        "Expected V2 role names to be based on V1 role's display name and numbered sequentially",
    )


def _assert_no_phantom_roles(test: TestCase, tuples: InMemoryTuples):
    """Check that there are no roles referenced in tuples that do not exist in the database."""
    # We are not consistent about actually creating PlatformRoleV2 models, so use the pre-configured values without
    # consulting the database.
    policy_service = GlobalPolicyIdService()

    def _uuid_for(access_type: DefaultAccessType, scope: Scope) -> Optional[str]:
        try:
            return str(platform_v2_role_uuid_for(access_type, scope, policy_service=policy_service))
        except DefaultGroupNotAvailableError:
            return None

    platform_role_uuids = {
        r
        for r in (_uuid_for(access_type, scope) for access_type in DefaultAccessType for scope in Scope)
        if r is not None
    }

    for v2_role_uuid in {
        *(t.resource_id for t in tuples.find_tuples(resource_type("rbac", "role"))),
        *(t.subject_id for t in tuples.find_tuples(subject_type("rbac", "role"))),
    }:
        if Role.objects.filter(system=True, uuid=v2_role_uuid).exists():
            # We are not interested in system roles here.
            continue

        if v2_role_uuid in platform_role_uuids:
            # We are not interested in platform roles here.
            continue

        v2_role = CustomRoleV2.objects.filter(uuid=v2_role_uuid).first()
        test.assertIsNotNone(v2_role, f"V2 Role with UUID {v2_role_uuid} exists in tuples but not in the database.")


def assert_v2_custom_roles_consistent(test: TestCase, tuples: Optional[InMemoryTuples]):
    binding_mappings_by_uuid = {
        str(m.mappings["id"]): m for m in BindingMapping.objects.filter(role__system=False).prefetch_related("role")
    }

    role_bindings_by_uuid = {str(b.uuid): b for b in RoleBinding.objects.filter(role__type=RoleV2.Types.CUSTOM)}

    # We should have the same UUIDs for both BindingMappings and RoleBindings.
    test.assertCountEqual(role_bindings_by_uuid.keys(), binding_mappings_by_uuid.keys())

    for role in Role.objects.filter(system=False):
        _assert_v2_names(test, role)

    for role in CustomRoleV2.objects.all():
        test.assertIsNotNone(role.v1_source, "All custom roles created through dual-write should have a v1_source.")

        _assert_role_mappings_consistent(
            test,
            role,
            [m for m in binding_mappings_by_uuid.values() if m.mappings["role"]["id"] == str(role.uuid)],
        )

        if tuples is not None:
            _assert_role_tuples_consistent(test, tuples, role)

    for binding_uuid, binding in role_bindings_by_uuid.items():
        mapping = binding_mappings_by_uuid[binding_uuid]

        _assert_binding_mapping_consistent(test, binding, mapping)

        # Principals should not be bound to custom roles.
        test.assertEqual(0, len(mapping.mappings["users"]))

        if tuples is not None:
            _assert_binding_tuples_consistent(test, tuples, binding)

    if tuples is not None:
        _assert_no_phantom_roles(test, tuples)


def assert_v2_system_role_bindings_consistent(test: TestCase, tuples: Optional[InMemoryTuples]):
    binding_mappings_by_uuid = {
        str(m.mappings["id"]): m for m in BindingMapping.objects.filter(role__system=True).prefetch_related("role")
    }

    role_bindings_by_uuid = {str(b.uuid): b for b in RoleBinding.objects.filter(role__type=RoleV2.Types.SEEDED)}

    # We should have the same UUIDs for both BindingMappings and RoleBindings.
    test.assertCountEqual(role_bindings_by_uuid.keys(), binding_mappings_by_uuid.keys())

    for binding_uuid, binding in role_bindings_by_uuid.items():
        _assert_binding_mapping_consistent(test, binding, binding_mappings_by_uuid[binding_uuid])

        if tuples is not None:
            _assert_binding_tuples_consistent(test, tuples, binding)


def assert_v2_roles_consistent(test: TestCase, tuples: Optional[InMemoryTuples]):
    assert_v2_custom_roles_consistent(test, tuples)
    assert_v2_system_role_bindings_consistent(test, tuples)


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
