# Generated by Django 4.2.14 on 2024-07-15 19:38

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("management", "0044_workspace"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="auditlog",
            name="principal",
        ),
    ]
