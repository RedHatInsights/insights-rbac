from typing import Union, Iterable
from unittest import TestCase

from management.role.model import BindingMapping, RoleV2
from management.role_binding.model import RoleBinding, RoleBindingGroup, RoleBindingPrincipal
from migration_tool.in_memory_tuples import all_of, resource_type, subject, relation, subject_type, InMemoryTuples
from migration_tool.models import v1_perm_to_v2_perm


def expect_v2_representation_invariants(test: TestCase, tuples: InMemoryTuples):
    expect_role_binding_invariants(test)
    expect_v2_tuple_invariants(test, tuples)


def expect_role_binding_invariants(test: TestCase):
    """Assert that the structures of all BindingMappings and RoleBindings are consistent with each other."""
    binding_mappings_by_id: dict[str, BindingMapping] = {b.mappings["id"]: b for b in BindingMapping.objects.all()}
    role_binding_by_uuid: dict[str, RoleBinding] = {str(b.uuid): b for b in RoleBinding.objects.all()}

    binding_mapping_uuids = set(binding_mappings_by_id.keys())
    role_binding_uuids = set(role_binding_by_uuid.keys())

    test.assertEqual(
        binding_mapping_uuids,
        role_binding_uuids,
        "Expected IDs from BindingMappings and IDs of RoleBindings to match.\n"
        f"From BindingMappings: {binding_mapping_uuids}\n"
        f"From RoleBindings: {role_binding_uuids}",
    )

    for mapping_id, mapping in binding_mappings_by_id.items():
        role_binding = role_binding_by_uuid[mapping_id]

        test.assertEqual(mapping.resource_type_namespace, role_binding.resource_type_namespace)
        test.assertEqual(mapping.resource_type_name, role_binding.resource_type_name)
        test.assertEqual(mapping.resource_id, role_binding.resource_id)

        test.assertEqual(mapping.mappings["role"]["id"], str(role_binding.role.uuid))

        mapping_role_is_system = mapping.mappings["role"]["is_system"]
        test.assertEqual(mapping_role_is_system, role_binding.role.type != RoleV2.Types.CUSTOM)

        if not mapping_role_is_system:
            test.assertEqual(
                set(mapping.mappings["role"]["permissions"]),
                {v1_perm_to_v2_perm(p) for p in role_binding.role.permissions.all()},
            )

        mapping_raw_users: Union[dict[str, str], Iterable[str]] = mapping.mappings["users"]
        mapping_users: list[tuple[str, str]] = (
            [(user_id, source_key) for source_key, user_id in mapping_raw_users.items()]
            if isinstance(mapping_raw_users, dict)
            else [(user_id, None) for user_id in mapping_raw_users]
        )

        binding_users = [
            (str(entry.principal.user_id), entry.source) for entry in role_binding.principal_entries.all()
        ]

        test.assertCountEqual(mapping_users, binding_users)

        test.assertCountEqual(
            mapping.mappings["groups"],
            [str(entry.group.uuid) for entry in role_binding.group_entries.all()],
        )


def expect_v2_tuple_invariants(test: TestCase, tuples: InMemoryTuples):
    """Assert that V2 models are consistent with the created tuples."""
    # Assert role permissions.
    test.assertEqual(
        {
            (str(role.uuid), v1_perm_to_v2_perm(permission))
            for role in RoleV2.objects.all()
            for permission in role.permissions.all()
        },
        {
            (r.resource_id, r.relation)
            for r in tuples.find_tuples(
                all_of(
                    resource_type("rbac", "role"),
                    subject("rbac", "principal", "*"),
                )
            )
        },
    )

    # Assert role parent-child relations.
    test.assertEqual(
        {(str(parent.uuid), str(child.uuid)) for parent in RoleV2.objects.all() for child in parent.children.all()},
        {
            (r.resource_id, r.subject_id)
            for r in tuples.find_tuples(
                all_of(
                    resource_type("rbac", "role"),
                    relation("child"),
                    subject_type("rbac", "role"),
                )
            )
        },
    )

    # Assert role <-> role binding relations.
    test.assertEqual(
        {(str(binding.uuid), str(binding.role.uuid)) for binding in RoleBinding.objects.all()},
        {
            (r.resource_id, r.subject_id)
            for r in tuples.find_tuples(
                all_of(
                    resource_type("rbac", "role_binding"),
                    relation("role"),
                )
            )
        },
    )

    # Assert role binding <-> resource relations.
    test.assertEqual(
        {
            ((binding.resource_type_namespace, binding.resource_type_name, binding.resource_id), str(binding.uuid))
            for binding in RoleBinding.objects.all()
        },
        {
            ((r.resource_type_namespace, r.resource_type_name, r.resource_id), r.subject_id)
            for r in tuples.find_tuples(all_of(relation("binding"), subject_type("rbac", "role_binding")))
        },
    )

    #  Assert role binding <-> group relations.
    test.assertEqual(
        {(str(entry.binding.uuid), str(entry.group.uuid)) for entry in RoleBindingGroup.objects.all()},
        {
            (r.resource_id, r.subject_id)
            for r in tuples.find_tuples(
                all_of(
                    resource_type("rbac", "role_binding"),
                    relation("subject"),
                    subject_type("rbac", "group", "member"),
                )
            )
        },
    )

    # Assert role binding <-> principal relations.
    test.assertEqual(
        {
            (str(entry.binding.uuid), str(entry.principal.principal_resource_id()))
            for entry in RoleBindingPrincipal.objects.all()
        },
        {
            (r.resource_id, r.subject_id)
            for r in tuples.find_tuples(
                all_of(
                    resource_type("rbac", "role_binding"),
                    relation("subject"),
                    subject_type("rbac", "principal"),
                )
            )
        },
    )
