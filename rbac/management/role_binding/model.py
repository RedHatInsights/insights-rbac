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

"""Models for role binding management."""

from typing import Iterable, Optional, Sequence

from django.db import models, transaction
from django.db.models import Count, Q, QuerySet
from management.exceptions import RequiredFieldError
from management.group.model import Group
from management.principal.model import Principal
from management.role.v2_model import RoleV2
from migration_tool.models import V2boundresource, V2rolebinding
from uuid_utils.compat import UUID, uuid7

from api.models import Tenant, TenantAwareModel


class RoleBinding(TenantAwareModel):
    """A role binding."""

    uuid = models.UUIDField(default=uuid7, editable=False, unique=True, null=False)
    role = models.ForeignKey("management.RoleV2", on_delete=models.CASCADE, related_name="bindings")

    resource_type = models.CharField(max_length=256, null=False)
    resource_id = models.CharField(max_length=256, null=False)

    def bound_groups(self) -> QuerySet:
        """Get a QuerySet for all groups bound to this RoleBinding."""
        return Group.objects.filter(role_binding_entries__in=self.group_entries.all())

    def update_groups(self, groups: Iterable[Group]):
        """Update the groups bound to this RoleBinding."""
        with transaction.atomic():
            self.group_entries.all().delete()
            RoleBindingGroup.objects.bulk_create([RoleBindingGroup(binding=self, group=g) for g in set(groups)])

    def update_groups_by_uuid(self, uuids: Iterable[UUID | str]):
        """
        Update the groups bound to this RoleBinding by UUID.

        Raises a ValueError if one of the UUIDs cannot be found.
        """
        uuids = set(str(u) for u in uuids)

        groups = Group.objects.filter(uuid__in=uuids).only("id", "uuid")
        found_uuids = {str(g.uuid) for g in groups}

        if found_uuids != uuids:
            missing_uuids = uuids.difference(found_uuids)
            raise ValueError(f"Not all expected groups could be found. Missing UUIDs: {missing_uuids}")

        # Group.uuid is unique, so at most one Group will be found per UUID, and len(groups) <= len(uuids).
        # By construction, len(found_uuids) <= len(groups).
        # We have just checked that found_uuids = uuids, so len(found_uuids) = len(uuids) <= len(groups) <= len(uuids).
        # Thus, len(groups) = len(uuids), and we have found one group for each specified UUID.

        self.update_groups(groups)

    def bound_principals(self) -> QuerySet:
        """Get a QuerySet for all principals bound to this RoleBinding."""
        return Principal.objects.filter(role_binding_entries__in=self.principal_entries.all()).distinct()

    def update_principals(self, principals_by_source: Iterable[tuple[str, Principal]]):
        """
        Update the principals bound to this RoleBinding.

        principals_by_source is an iterable of pairs of the source string and the principal added from that source.
        """
        with transaction.atomic():
            self.principal_entries.all().delete()

            RoleBindingPrincipal.objects.bulk_create(
                [RoleBindingPrincipal(binding=self, principal=p, source=s) for s, p in set(principals_by_source)]
            )

    def update_principals_by_user_id(self, user_ids_by_source: Iterable[tuple[str, str]]):
        """
        Update the principals bound to this RoleBinding by user_id.

        principals_by_source is an iterable of pairs of the source string and the user_id of the principal added from
        that source.

        A ValueError is raised if one of the user IDs cannot be found or if multiple principals are associated with
        one of the provided user IDs.
        """
        user_ids_by_source = set(user_ids_by_source)
        user_ids = set(entry[1] for entry in user_ids_by_source)

        if None in user_ids:
            raise TypeError("None user IDs are not supported.")

        principals = Principal.objects.filter(user_id__in=user_ids)
        found_user_ids: set[str] = {p.user_id for p in principals}

        if found_user_ids != user_ids:
            missing_user_ids = user_ids.difference(found_user_ids)
            raise ValueError(f"Not all expected principals could be found. Missing user IDs: {missing_user_ids}")

        # Principal.user_id is unique, so at most one Principal will be found per user ID, and we have:
        #   len(principals) <= len(user_ids).
        # By construction, len(found_user_ids) <= len(principals).
        # We have just checked that found_user_ids = user_ids, so we have:
        #   len(found_user_ids) = len(user_ids) <= len(principals) <= len(user_ids).
        # Thus, len(user_ids) = len(principals), and we have found one group for each specified UUID.

        principals_by_id = {p.user_id: p for p in principals}
        self.update_principals((s, principals_by_id[u]) for s, u in user_ids_by_source)

    def as_migration_value(self, force_group_uuids: Optional[list[str]] = None) -> V2rolebinding:
        """
        Return the V2rolebinding equivalent of this role binding.

        group_uuids is provided in the case where
        """
        if force_group_uuids is None:
            force_group_uuids = [str(u) for u in self.bound_groups().values_list("uuid", flat=True)]

        return V2rolebinding(
            id=str(self.uuid),
            role=self.role.as_migration_value(),
            resource=V2boundresource(
                # TODO: we currently assume all resources types are in namespace "rbac". This is currently true for
                #  all the types we care about, but is not necessarily true in general. The semantics of the
                #  Inventory API (which we will eventually have to migrate to) are different and do not have a
                #  resource type namespace, per se.
                resource_type=("rbac", self.resource_type),
                resource_id=self.resource_id,
            ),
            groups=force_group_uuids,
            users={},
        )

    @classmethod
    def set_roles_for_subject(
        cls,
        tenant: Tenant,
        resource_type: str,
        resource_id: str,
        subject: Group | Principal,
        roles: Sequence[RoleV2],
    ) -> None:
        """Set the roles for a subject on a resource.

        Replaces all existing role bindings for the subject on the resource
        with the provided roles. This is an atomic operation.

        Args:
            tenant: The tenant context
            resource_type: The type of resource (e.g., 'workspace')
            resource_id: The resource identifier
            subject: The subject (Group or Principal) to update bindings for
            roles: The roles to assign to the subject

        Raises:
            RequiredFieldError: If required parameters are missing
        """
        if not resource_type:
            raise RequiredFieldError("resource_type")
        if not resource_id:
            raise RequiredFieldError("resource_id")
        if not roles:
            raise RequiredFieldError("roles")

        if isinstance(subject, Group):
            cls._set_roles_impl(
                tenant,
                resource_type,
                resource_id,
                roles,
                through_model=RoleBindingGroup,
                subject_field="group",
                subject=subject,
            )
        else:
            cls._set_roles_impl(
                tenant,
                resource_type,
                resource_id,
                roles,
                through_model=RoleBindingPrincipal,
                subject_field="principal",
                subject=subject,
                extra_defaults={"source": "v2_api"},
            )

    @classmethod
    def _set_roles_impl(
        cls,
        tenant: Tenant,
        resource_type: str,
        resource_id: str,
        roles: Sequence[RoleV2],
        through_model: "type[RoleBindingGroup] | type[RoleBindingPrincipal]",
        subject_field: str,
        subject: Group | Principal,
        extra_defaults: Optional[dict] = None,
    ) -> None:
        """Shared implementation for setting roles on a subject."""
        # Find existing bindings for this subject on this resource
        filter_kwargs = {
            subject_field: subject,
            "binding__resource_type": resource_type,
            "binding__resource_id": resource_id,
            "binding__tenant": tenant,
        }
        existing_binding_ids = list(through_model.objects.filter(**filter_kwargs).values_list("binding_id", flat=True))

        # Remove subject from these bindings
        through_model.objects.filter(**{subject_field: subject}, binding_id__in=existing_binding_ids).delete()

        # Clean up orphaned bindings
        cls._cleanup_orphaned_bindings(existing_binding_ids)

        # Create new bindings for each role
        for role in roles:
            binding, _ = cls.objects.get_or_create(
                role=role,
                resource_type=resource_type,
                resource_id=resource_id,
                tenant=tenant,
            )
            create_kwargs = {subject_field: subject, "binding": binding}
            if extra_defaults:
                create_kwargs.update(extra_defaults)
            through_model.objects.get_or_create(**create_kwargs)

    @classmethod
    def _cleanup_orphaned_bindings(cls, binding_ids: Sequence[int]) -> None:
        """Remove bindings that have no groups or principals attached."""
        if not binding_ids:
            return

        cls.objects.filter(id__in=binding_ids).annotate(
            group_count=Count("group_entries"),
            principal_count=Count("principal_entries"),
        ).filter(group_count=0, principal_count=0).delete()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["role", "resource_type", "resource_id", "tenant"],
                name="unique role binding per role resource pair per tenant",
            ),
        ]


class RoleBindingGroup(models.Model):
    """The relationship between a RoleBinding and one of its group subjects."""

    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="role_binding_entries")
    binding = models.ForeignKey(RoleBinding, on_delete=models.CASCADE, related_name="group_entries")

    class Meta:
        constraints = [models.UniqueConstraint(fields=["group", "binding"], name="unique group binding pair")]


class RoleBindingPrincipal(models.Model):
    """The relationship between a RoleBinding and one of its principal subjects."""

    principal = models.ForeignKey(Principal, on_delete=models.CASCADE, related_name="role_binding_entries")
    binding = models.ForeignKey(RoleBinding, on_delete=models.CASCADE, related_name="principal_entries")
    source = models.CharField(max_length=128, null=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["principal", "binding", "source"], name="unique principal binding source triple"
            ),
            models.CheckConstraint(condition=~Q(source=""), name="role binding principal has source"),
        ]
