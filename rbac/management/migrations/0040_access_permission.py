# Generated by Django 3.2.17 on 2023-02-16 21:28

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("management", "0039_auto_20230127_1942"),
    ]
    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(code=migrations.RunPython.noop, reverse_code=migrations.RunPython.noop)
            ],
            state_operations=[
                migrations.AddField(
                    model_name="access",
                    name="permission",
                    field=models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="accesses",
                        to="management.permission",
                    ),
                ),
            ],
        )
    ]
