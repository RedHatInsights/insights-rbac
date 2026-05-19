import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("management", "0087_alter_extrolerelation_ext_id_alter_exttenant_name"),
    ]

    operations = [
        migrations.AddField(
            model_name="bindingmapping",
            name="v2_role",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="binding_mappings",
                to="management.rolev2",
            ),
        ),
        migrations.AddIndex(
            model_name="bindingmapping",
            index=models.Index(
                fields=["role", "resource_type_namespace", "resource_type_name", "resource_id"],
                name="bm_role_resource_idx",
            ),
        ),
    ]
