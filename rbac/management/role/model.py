#
# Copyright 2019 Red Hat, Inc.
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

"""Model for role management."""
import logging
from typing import Optional, Union, Set
from uuid import uuid4

from django.conf import settings
from django.db import models
from django.db.models import signals
from django.utils import timezone

from api.models import FilterQuerySet, TenantAwareModel
from internal.integration import sync_handlers
from management.cache import AccessCache, skip_purging_cache_for_public_tenant
from management.models import Permission, Principal
from management.rbac_fields import AutoDateTimeField
from management.workspace.model import Workspace
from migration_tool.models import (
    V2boundresource,
    V2role,
    V2rolebinding,
    role_binding_group_subject_tuple,
    role_binding_user_subject_tuple,
)
from migration_tool.in_memory_tuples import Relationship
import uuid

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class Role(TenantAwareModel):
    """A role."""

    uuid = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
    name = models.CharField(max_length=150)
    display_name = models.CharField(default="", max_length=150)
    description = models.TextField(null=True)
    system = models.BooleanField(default=False)
    platform_default = models.BooleanField(default=False)
    version = models.PositiveIntegerField(default=1)
    created = models.DateTimeField(default=timezone.now)
    modified = AutoDateTimeField(default=timezone.now)
    admin_default = models.BooleanField(default=False)
    objects = FilterQuerySet.as_manager()

    @property
    def role(self):
        """Get role for self."""
        return self

    class Meta:
        ordering = ["name", "modified"]
        constraints = [
            models.UniqueConstraint(fields=["name", "tenant"], name="unique role name per tenant"),
            models.UniqueConstraint(fields=["display_name", "tenant"], name="unique role display name per tenant"),
        ]

    def save(self, *args, **kwargs):
        """Ensure that display_name is populated on save."""
        if not self.display_name:
            self.display_name = self.name
        super(Role, self).save(*args, **kwargs)

    def external_role_id(self):
        """Return external role id."""
        return self.ext_relation.ext_id if hasattr(self, "ext_relation") else None

    def external_tenant_name(self):
        """Return external tenant name."""
        return self.ext_relation.ext_tenant.name if hasattr(self, "ext_relation") else None


class Access(TenantAwareModel):
    """An access object."""

    permission = models.ForeignKey(Permission, null=True, on_delete=models.CASCADE, related_name="accesses")
    role = models.ForeignKey(Role, null=True, on_delete=models.CASCADE, related_name="access")

    def permission_application(self):
        """Return the application name from the permission."""
        return self.permission.application


class ResourceDefinition(TenantAwareModel):
    """A resource definition."""

    attributeFilter = models.JSONField(default=dict)
    access = models.ForeignKey(Access, null=True, on_delete=models.CASCADE, related_name="resourceDefinitions")
    workspaces = models.ManyToManyField(Workspace, through="ResourceDefinitionsWorkspaces")

    @property
    def role(self):
        """Get role for RD."""
        if self.access:
            return self.access.role

    @property
    def application(self):
        """Get the corresponding application."""
        if self.access and self.access.permission:
            return self.access.permission.application

    @property
    def resource_type(self):
        """Get the corresponding resource type."""
        if self.access and self.access.permission:
            return self.access.permission.resource_type

    @property
    def tenant_id(self):
        """Get the tenant_id of the RD."""
        if self.tenant:
            return self.tenant.id

    def save(self, *args, **kwargs):
        """Save the resource definition and link workspaces."""
        super().save(*args, **kwargs)

        # Link workspaces based on the ones specified in the "attributeFilter".
        self._link_workspaces()

    def _link_workspaces(self):
        """Links the resource definition to workspaces specified in the attribute filters."""
        # Ignore any resource definitions that do not have the "group.id" key.
        key: str = self.attributeFilter.get("key", "")

        if key != "group.id":
            logger.info(
                f"[resource_definition_id: {self.id}][tenant_id: {self.tenant_id}] Linking "
                f'resource definition to workspaces skipped because the resource definition\'s key "{key}" does not '
                f'have the expected "group.id" value'
            )
            return

        # Get the resource definition's operation and value.
        operation: str = self.attributeFilter.get("operation", "")
        value: Union[str, list[Union[None, int, str]]] = self.attributeFilter.get("value", [])

        # Extract the workspace IDs.
        str_ids_to_convert: list[str] = []
        match operation:
            case "equal":
                str_ids_to_convert.append(value)
            case "in":
                for element in value:
                    if isinstance(element, str):
                        str_ids_to_convert.append(element)
            case _:
                logger.warning(
                    f'[resource_definition_id: "{self.id}"] Unable to create relation between the resource '
                    f'definition and the workspace because the operation "{operation}" is unrecognized'
                )
                return

        # Parse the workspace IDs as UUIDs.
        parsed_workspace_ids: Set[uuid.UUID] = set()
        for str_id in str_ids_to_convert:
            try:
                parsed_workspace_ids.add(uuid.UUID(str_id))
            except (AttributeError, TypeError, ValueError) as e:
                logger.error(
                    f'[resource_definition_id: "{self.id}"] Unable to parse workspace ID "{str_id}" as a '
                    f"valid UUID: {str(e)}"
                )

        # Fetch all the "new" workspaces specified in the resource definition.
        workspaces: set[Workspace] = set(Workspace.objects.filter(id__in=parsed_workspace_ids))

        # Fetch all the existing links for the current resource definition.
        # This will help us figure out which links need to be removed and
        # which ones need to be created.
        existing_rdws: list[ResourceDefinitionsWorkspaces] = ResourceDefinitionsWorkspaces.objects.filter(
            resource_definition=self
        )
        existing_linked_workspaces: set[Workspace] = set()
        for rdw in existing_rdws:
            existing_linked_workspaces.add(rdw.workspace)

        # The difference between the "existing linked workspaces" and the
        # "new workspaces to link" will give us the workspaces that only exist
        # in the former set, which means that those are the ones we need to
        # remove from the database.
        to_remove = existing_linked_workspaces.difference(workspaces)

        if to_remove:
            ResourceDefinitionsWorkspaces.objects.filter(resource_definition=self, workspace__in=to_remove).delete()

            for workspace in to_remove:
                logger.info(
                    f'[resource_definition_id: "{self.id}"][tenant_id: "{self.tenant_id}"]'
                    f'[workspace_id: "{workspace.id}"] Link removed'
                )

        # Performing a difference between the "new workspaces" with the
        # "existing" ones, will, on the other hand, tell us which new links
        # need to be created.
        for workspace_to_insert in workspaces.difference(existing_linked_workspaces):
            ResourceDefinitionsWorkspaces.objects.create(
                resource_definition=self, workspace=workspace_to_insert, tenant=self.tenant
            )

            logger.info(
                f'[resource_definition_id: "{self.id}"][tenant_id: "{self.tenant_id}"]'
                f"[workspace_id: {workspace_to_insert.id}] Linked resource definition and workspace"
            )

            # Remove the workspace ID from the parsed ones, to keep track of which
            # ones have been processed.
            parsed_workspace_ids.remove(workspace_to_insert.id)

        # When the set contains elements, it means that not all of the set's IDs
        # were returned from the query, thus signaling that some of the workspace
        # IDs do not exist in our database.
        for pwid in parsed_workspace_ids:
            logger.warning(
                f'[resource_definition_id: "{self.id}"][tenant_id: "{self.tenant_id}"]'
                f'[workspace_id: "{pwid}"] RBAC does not have a workspace record for the parsed workspace ID from the '
                f"resource definition"
            )


class ExtTenant(models.Model):
    """External tenant."""

    name = models.CharField(max_length=20, null=False, unique=True)


class ExtRoleRelation(models.Model):
    """External relation info of role."""

    ext_tenant = models.ForeignKey(ExtTenant, null=True, on_delete=models.CASCADE, related_name="ext_role_relation")
    ext_id = models.CharField(max_length=20, null=False)
    role = models.OneToOneField(Role, on_delete=models.CASCADE, null=False, related_name="ext_relation")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["ext_tenant", "ext_id"], name="unique external id per external tenant")
        ]


class SourceKey:
    """Key for a source."""

    key: str

    def __init__(self, source, source_id: str):
        """Init method."""
        self.key = f"{source.__class__.__name__}/{source_id}"

    def __hash__(self):
        """Hash value for the SourceKey instance."""
        return hash(self.key)

    def __str__(self):
        """Return the string representation of the SourceKey instance."""
        return f"{self.key}"


class BindingMapping(models.Model):
    """V2 binding Mapping definition."""

    # JSON encoding of migration_tool.models.V2rolebinding
    mappings = models.JSONField(default=dict)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="binding_mappings")
    resource_type_namespace = models.CharField(max_length=256, null=False)
    resource_type_name = models.CharField(max_length=256, null=False)
    resource_id = models.CharField(max_length=256, null=False)

    @classmethod
    def for_role_binding(cls, role_binding: V2rolebinding, v1_role: Union[Role, str]):
        """Create a new BindingMapping for a V2rolebinding."""
        mappings = role_binding.as_minimal_dict()
        resource = role_binding.resource
        resource_type_namespace = resource.resource_type[0]
        resource_type_name = resource.resource_type[1]
        resource_id = resource.resource_id
        role_arg: dict[str, Union[Role, str]] = (
            {"role": v1_role} if isinstance(v1_role, Role) else {"role_id": v1_role}
        )
        return cls(
            mappings=mappings,
            **role_arg,
            resource_type_namespace=resource_type_namespace,
            resource_type_name=resource_type_name,
            resource_id=resource_id,
        )

    def as_tuples(self) -> list[Relationship]:
        """Create tuples from BindingMapping model."""
        v2_role_binding = self.get_role_binding()
        return v2_role_binding.as_tuples()

    def is_unassigned(self):
        """Return true if mapping is not assigned to any groups or users."""
        return len(self.mappings.get("groups", [])) == 0 and len(self.mappings.get("users", [])) == 0

    def unassign_group(self, group_uuid) -> Optional[Relationship]:
        """
        Completely unassign this group from the mapping, even if it is assigned more than once.

        Returns the Relationship for this Group.
        """
        relationship = None
        while True:
            relationship = self.pop_group_from_bindings(group_uuid)
            if relationship is not None:
                break
        return relationship

    def pop_group_from_bindings(self, group_uuid: str) -> Optional[Relationship]:
        """
        Pop the group from mappings.

        The group may still be bound to the role in other ways, so the group may still be included in the binding
        more than once after this method returns.

        If the group is no longer assigned at all, the Relationship is returned to be removed.

        If you wish to remove the group entirely (and know it is safe to do so!), use [unassign_group].
        """
        if group_uuid in self.mappings["groups"]:
            self.mappings["groups"].remove(group_uuid)
        if group_uuid in self.mappings["groups"]:
            return None
        return role_binding_group_subject_tuple(self.mappings["id"], group_uuid)

    def assign_group_to_bindings(self, group_uuid: str) -> Optional[Relationship]:
        """
        Assign group to mappings.

        If the group entry already exists, skip it.
        """
        if group_uuid in self.mappings["groups"]:
            return None
        self.mappings["groups"].append(group_uuid)
        return role_binding_group_subject_tuple(self.mappings["id"], group_uuid)

    # TODO: This can be deleted after the migration
    def add_group_to_bindings(self, group_uuid: str) -> Relationship:
        """
        Add group to mappings.

        This adds an additional entry for the group, even if the group is already assigned, to account for multiple
        possible sources that may have assigned the group for the same role and resource.
        """
        self.mappings["groups"].append(group_uuid)
        return role_binding_group_subject_tuple(self.mappings["id"], group_uuid)

    def unassign_user_from_bindings(self, user_id: str, source: Optional[SourceKey] = None) -> Optional[Relationship]:
        """Unassign user from mappings."""
        self._remove_value_from_mappings("users", user_id, source)
        users_list = (
            self.mappings["users"] if isinstance(self.mappings["users"], list) else self.mappings["users"].values()
        )
        if user_id in users_list:
            logging.info(
                f"[Dual Write] user {user_id} still in mappings of bindingmapping {self.pk}, "
                "therefore, no relation to remove. "
            )
            return None
        return role_binding_user_subject_tuple(self.mappings["id"], user_id)

    def update_data_format_for_user(self, all_relations_to_remove):
        """Update data format for users in mappings."""
        if isinstance(self.mappings["users"], list):
            existing_user_ids = list(self.mappings["users"])
            for existing_user_id in existing_user_ids:
                relations_to_remove = self.unassign_user_from_bindings(existing_user_id)
                if relations_to_remove is not None:
                    all_relations_to_remove.append(relations_to_remove)
            self.mappings["users"] = {}

    def assign_user_to_bindings(self, user_id: str, source: Optional[SourceKey] = None) -> Relationship:
        """Assign user to mappings."""
        self._add_value_to_mappings("users", user_id, source)
        return role_binding_user_subject_tuple(self.mappings["id"], user_id)

    def update_mappings_from_role_binding(self, role_binding: V2rolebinding):
        """Set mappings."""
        # Validate resource and v1 role match
        resource = role_binding.resource
        if (
            resource.resource_type[0] != self.resource_type_namespace
            or resource.resource_type[1] != self.resource_type_name
            or resource.resource_id != self.resource_id
        ):
            raise Exception(
                "Resource mismatch."
                f"Expected: {self.resource_type_namespace}:{self.resource_type_name}:{self.resource_id} "
                f"but got: {resource.resource_type[0]}:{resource.resource_type[1]}:{resource.resource_id} "
            )

        self.mappings = role_binding.as_minimal_dict()

    def get_role_binding(self) -> V2rolebinding:
        """Get role binding."""
        args = {**self.mappings}
        args["resource"] = V2boundresource(
            resource_type=(self.resource_type_namespace, self.resource_type_name), resource_id=self.resource_id
        )
        args["role"] = V2role(
            id=args["role"]["id"],
            is_system=args["role"]["is_system"],
            permissions=frozenset(args["role"]["permissions"]),
        )
        return V2rolebinding(**args)

    def _remove_value_from_mappings(self, field, value, source):
        """Update mappings by removing value."""
        if isinstance(self.mappings[field], dict):
            self.mappings[field].pop(str(source), None)
        else:
            self.mappings[field].remove(value)

    def _add_value_to_mappings(self, field, value, source):
        """Update mappings by adding value."""
        if isinstance(self.mappings[field], dict):
            self.mappings[field].update({str(source): value})
        else:
            self.mappings[field].append(value)


class ResourceDefinitionsWorkspaces(TenantAwareModel):
    """A model that represents the join table between the resource definitions and the workspaces."""

    resource_definition = models.ForeignKey(on_delete=models.CASCADE, to=ResourceDefinition)
    workspace = models.ForeignKey(on_delete=models.CASCADE, to=Workspace)


def role_related_obj_change_cache_handler(sender=None, instance=None, using=None, **kwargs):
    """Signal handler for invalidating Principal cache on Role object change."""
    if skip_purging_cache_for_public_tenant(instance.tenant):
        return
    logger.info(
        "Handling signal for added/removed/changed role-related object %s - "
        "invalidating associated user cache keys",
        instance,
    )
    cache = AccessCache(instance.tenant.org_id)
    if instance.role:
        for principal in Principal.objects.filter(group__policies__roles__pk=instance.role.pk):
            cache.delete_policy(principal.uuid)


def role_related_obj_change_sync_handler(sender=None, instance=None, using=None, **kwargs):
    """Signal handler for informing external sync of Role object changes."""
    logger.info(
        "Handling signal for added/removed/changed role-related object %s - " "informing sync topic",
        instance,
    )
    if instance.role:
        sync_handlers.send_sync_message(
            event_type="role_modified", payload={"role": {"name": instance.role.name, "uuid": str(instance.role.uuid)}}
        )


if settings.ACCESS_CACHE_ENABLED and settings.ACCESS_CACHE_CONNECT_SIGNALS:
    signals.pre_delete.connect(role_related_obj_change_cache_handler, sender=Role)
    signals.pre_delete.connect(role_related_obj_change_cache_handler, sender=Access)
    signals.pre_delete.connect(role_related_obj_change_cache_handler, sender=ResourceDefinition)
    signals.post_save.connect(role_related_obj_change_cache_handler, sender=Role)
    signals.post_save.connect(role_related_obj_change_cache_handler, sender=Access)
    signals.post_save.connect(role_related_obj_change_cache_handler, sender=ResourceDefinition)

if settings.KAFKA_ENABLED:
    signals.pre_delete.connect(role_related_obj_change_sync_handler, sender=Role)
    signals.pre_delete.connect(role_related_obj_change_sync_handler, sender=Access)
    signals.pre_delete.connect(role_related_obj_change_sync_handler, sender=ResourceDefinition)
    signals.post_save.connect(role_related_obj_change_sync_handler, sender=Role)
    signals.post_save.connect(role_related_obj_change_sync_handler, sender=Access)
    signals.post_save.connect(role_related_obj_change_sync_handler, sender=ResourceDefinition)
