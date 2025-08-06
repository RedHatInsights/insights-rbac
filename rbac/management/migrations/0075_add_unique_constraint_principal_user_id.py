from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("management", "0074_alter_rolev2_name"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="principal",
            constraint=models.UniqueConstraint(fields=["user_id"], name="management_principal_user_id_key"),
        )
    ]
