# Generated by Django 4.2.10 on 2024-08-16 02:29

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        (
            "management",
            "0046_remove_workspace_the_combination_of_name_tenant_and_parent_must_be_unique__and_more",
        ),
    ]

    operations = [
        migrations.CreateModel(
            name="RoleMapping",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "v1_role",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="management.role",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="V2Role",
            fields=[
                (
                    "id",
                    models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False),
                ),
                ("is_system", models.BooleanField(default=False)),
                (
                    "v1_roles",
                    models.ManyToManyField(through="management.RoleMapping", to="management.role"),
                ),
            ],
        ),
        migrations.AddField(
            model_name="rolemapping",
            name="v2_role",
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="management.v2role"),
        ),
        migrations.CreateModel(
            name="BindingMapping",
            fields=[
                (
                    "id",
                    models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False),
                ),
                (
                    "v1_role",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="management.role",
                    ),
                ),
            ],
        ),
    ]