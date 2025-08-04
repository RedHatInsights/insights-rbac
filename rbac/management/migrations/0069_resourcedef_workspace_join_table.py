import logging
import uuid

from django.db import migrations, models
from django.db.backends.postgresql.schema import DatabaseSchemaEditor
from django.db.migrations.state import StateApps

from management.role.model import ResourceDefinition
from management.workspace.model import Workspace


def link_resource_definitions_workspaces(apps: StateApps, schema_editor: DatabaseSchemaEditor):
    """Links the existing resource definitions to workspaces."""
    resource_definition_model = apps.get_model("management", "ResourceDefinition")
    resource_definitions_workspaces_model = apps.get_model("management", "ResourceDefinitionsWorkspaces")
    workspace_model = apps.get_model("management", "Workspace")

    # Flag elements for fetching and looping through database results.
    keep_fetching = True
    limit = 500
    offset = 0

    # Grab resource definitions in batches to avoid hitting memory limits or
    # overloading the database with too many queries.
    while keep_fetching:
        linked_resources = 0
        fetched_resource_definitions: list[ResourceDefinition] = resource_definition_model.objects.filter(
            attributeFilter__key="group.id"
        )[offset:limit]

        for resourcedef in fetched_resource_definitions:
            value = resourcedef.attributeFilter.get("value")

            # Extract the workspace IDs from the JSON structure. We have
            # either a list of values or a value itself, so we need to be
            # careful with the processing.
            workspace_ids: list[uuid.UUID] = []
            if isinstance(value, list):
                # Some of the values contain non-UUIDs like "null" and "1"
                # values which we need to ignore.
                for list_item in value:
                    try:
                        workspace_ids.append(uuid.UUID(list_item))
                    except (AttributeError, TypeError):
                        print(
                            f'[resource_definition_id: "{resourcedef.id}"] Invalid or non-UUID value "{list_item}" ignored for resource definition'
                        )
                        continue

            if isinstance(value, str):
                workspace_ids.append(uuid.UUID(value))

            # Fetch the workspaces by using the IDs we just extracted.
            fetched_workspaces: list[Workspace] = workspace_model.objects.filter(id__in=workspace_ids)

            # Log any discrepancies. We do this instead of using single
            # workspace fetching queries to reduce the load.
            fetched_workspaces_ids: list[uuid.UUID] = []
            for fetched_workspace in fetched_workspaces:
                fetched_workspaces_ids.append(fetched_workspace.id)

            for workspace_id in workspace_ids:
                if workspace_id not in fetched_workspaces_ids:
                    print(
                        f'[resource_definition_id: "{resourcedef.id}"][workspace_id: "{workspace_id}"] Workspace not found in database'
                    )

            # Create the link in the join table
            for fetched_workspace in fetched_workspaces:
                if resourcedef.tenant != fetched_workspace.tenant:
                    print(
                        f"[resource_definition_id: {resourcedef.id}][workspace_id: {fetched_workspace.id}] Tenant mismatch detected. Skipping linking..."
                    )
                    continue

                resource_definitions_workspaces_model.objects.create(
                    resource_definition=resourcedef, workspace=fetched_workspace, tenant=resourcedef.tenant
                )
                linked_resources += 1

        print(f'[limit: "{limit}"][offset: "{offset}"] Linked {linked_resources} resource definitions')

        keep_fetching = len(fetched_resource_definitions) != 0
        offset += len(fetched_resource_definitions)


class Migration(migrations.Migration):

    dependencies = [
        (
            "management",
            "0068_alter_workspace_type",
        ),
    ]

    operations = [
        migrations.CreateModel(
            name="ResourceDefinitionsWorkspaces",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "resource_definition",
                    models.ForeignKey(on_delete=models.CASCADE, to="management.resourcedefinition"),
                ),
                ("workspace", models.ForeignKey(on_delete=models.CASCADE, to="management.workspace")),
                ("tenant", models.ForeignKey(on_delete=models.CASCADE, to="api.tenant")),
            ],
        ),
        migrations.RunPython(link_resource_definitions_workspaces),
    ]
