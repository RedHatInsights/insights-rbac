from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("management", "0089_backfill_bindingmapping_v2_role"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="bindingmapping",
            constraint=models.UniqueConstraint(
                fields=["v2_role", "resource_type_namespace", "resource_type_name", "resource_id"],
                name="unique_bindingmapping_v2role_resource",
            ),
        ),
    ]
