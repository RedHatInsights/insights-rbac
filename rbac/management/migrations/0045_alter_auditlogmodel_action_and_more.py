# Generated by Django 4.1.7 on 2023-08-31 18:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("management", "0044_alter_auditlogmodel_action"),
    ]

    operations = [
        migrations.AlterField(
            model_name="auditlogmodel",
            name="action",
            field=models.CharField(
                choices=[
                    ("delete", "delete"),
                    ("add", "add"),
                    ("edit", "edit"),
                    ("create", "create"),
                    ("remove", "remove"),
                ],
                max_length=32,
            ),
        ),
        migrations.AlterField(
            model_name="auditlogmodel",
            name="resource",
            field=models.CharField(
                choices=[
                    ("group", "group"),
                    ("role", "role"),
                    ("user", "user"),
                    ("permission", "permission"),
                ],
                max_length=32,
            ),
        ),
    ]
