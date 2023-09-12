# Generated by Django 4.1.7 on 2023-08-28 12:10

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0014_auto_20220726_1743"),
        ("management", "0040_access_permission"),
    ]

    operations = [
        migrations.CreateModel(
            name="Workspace",
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
                ("path", models.CharField(max_length=255, unique=True)),
                ("depth", models.PositiveIntegerField()),
                ("numchild", models.PositiveIntegerField(default=0)),
                ("name", models.CharField(max_length=100)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.AddField(
            model_name="permission",
            name="workspace",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="permissions",
                to="management.workspace",
            ),
        ),
    ]
