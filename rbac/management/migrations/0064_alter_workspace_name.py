# Generated by Django 4.2.16 on 2025-02-18 19:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "management",
            "0063_remove_workspace_unique_default_root_workspace_per_tenant_and_more",
        ),
    ]

    operations = [
        migrations.AlterField(
            model_name="workspace",
            name="name",
            field=models.CharField(db_index=True, max_length=255),
        ),
    ]
