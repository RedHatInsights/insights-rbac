# Generated by Django 4.2.16 on 2024-10-24 20:26

from django.db import migrations, models
import uuid_utils.compat


class Migration(migrations.Migration):

    dependencies = [
        ("management", "0056_alter_tenantmapping_tenant"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="workspace",
            name="id",
        ),
        migrations.RemoveField(
            model_name="workspace",
            name="parent",
        ),
        migrations.AlterField(
            model_name="workspace",
            name="uuid",
            field=models.UUIDField(
                default=uuid_utils.compat.uuid7,
                editable=False,
                primary_key=True,
                serialize=False,
                unique=True,
            ),
        ),
    ]
