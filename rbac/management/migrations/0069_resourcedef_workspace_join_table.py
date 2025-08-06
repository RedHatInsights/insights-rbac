import uuid

from django.db import migrations, models
from django.db.backends.postgresql.schema import DatabaseSchemaEditor
from django.db.migrations.state import StateApps

from management.role.model import ResourceDefinitionsWorkspaces


def link_resource_definitions_workspaces(apps: StateApps, schema_editor: DatabaseSchemaEditor):
    """Links the existing resource definitions to workspaces."""
    resource_definition_model = apps.get_model("management", "ResourceDefinition")
    resource_definitions_workspaces_model = apps.get_model("management", "ResourceDefinitionsWorkspaces")
    workspace_model = apps.get_model("management", "Workspace")

    #  Define a batch size to fetch a bunch of resource definitions each time.
    batch_size = 500

    # Iterate over the database's resource definitions.
    for resource_definition in resource_definition_model.objects.filter(attributeFilter__key="group.id").iterator(
        chunk_size=batch_size
    ):
        value = resource_definition.attributeFilter.get("value")

        # Get the workspace IDs defined in the resource definition.
        raw_workspace_ids: list[str]
        if isinstance(value, str):
            raw_workspace_ids = [value]
        else:
            raw_workspace_ids = value

        # Convert the raw strings into UUIDs.
        rdef_workspace_ids: set[uuid.UUID] = set()
        for rwi in raw_workspace_ids:
            try:
                rdef_workspace_ids.add(uuid.UUID(rwi))
            except (AttributeError, TypeError, ValueError):
                f'[resource_definition_id: "{resource_definition.id}"] Invalid or non-UUID value "{rwi}" ignored for resource definition'

        # Fetch all the workspaces from the database.
        database_workspaces = workspace_model.objects.filter(id__in=rdef_workspace_ids)

        # Grab the database workspaces' IDs to be able to compare them.
        database_workspace_ids: set[uuid.UUID] = set()
        for dw in database_workspaces:
            database_workspace_ids.add(dw.id)

        # The difference between the resource definition's workspace IDs and
        # the database's workspace IDs will give us which ones are not present
        # in the database.
        for non_existent_wid_db in rdef_workspace_ids.difference(database_workspace_ids):
            print(
                f'[resource_definition_id: "{resource_definition.id}"][workspace_id: "{non_existent_wid_db}"] Workspace not found in database'
            )

        # Verify that the tenants are correct before preparing the set of
        # resources to batch insert them.
        links_to_create: set[ResourceDefinitionsWorkspaces] = set()
        for db_workspace in database_workspaces:
            if db_workspace.tenant != resource_definition.tenant:
                print(
                    f"[resource_definition_id: {resource_definition.id}][workspace_id: {resource_definition.id}] Tenant mismatch detected. Skipping linking..."
                )

            links_to_create.add(
                ResourceDefinitionsWorkspaces(
                    resource_definition=resource_definition, workspace=db_workspace, tenant=resource_definition.tenant
                )
            )

        # Bulk create the resources.
        resource_definitions_workspaces_model.objects.bulk_create(links_to_create)


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
        migrations.AddConstraint(
            model_name="ResourceDefinitionsWorkspaces",
            constraint=models.UniqueConstraint(
                name="unique resource definition and workspace link per tenant",
                fields=["resource_definition", "workspace", "tenant"],
            ),
        ),
        migrations.RunPython(link_resource_definitions_workspaces),
    ]
