from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("management", "0069_auditlog_resource_uuid_and_more"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="principal",
            constraint=models.UniqueConstraint(fields=["user_id"], name="management_principal_user_id_key"),
        )
    ]
