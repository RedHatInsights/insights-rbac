# Generated by Django 2.2.4 on 2021-04-20 16:20

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("management", "0032_auto_20210304_1534"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="group",
            constraint=models.UniqueConstraint(fields=("name", "tenant"), name="unique group name per tenant"),
        ),
        migrations.AddConstraint(
            model_name="policy",
            constraint=models.UniqueConstraint(fields=("name", "tenant"), name="unique policy name per tenant"),
        ),
        migrations.AddConstraint(
            model_name="principal",
            constraint=models.UniqueConstraint(
                fields=("username", "tenant"), name="unique principal username per tenant"
            ),
        ),
        migrations.AddConstraint(
            model_name="role",
            constraint=models.UniqueConstraint(fields=("name", "tenant"), name="unique role name per tenant"),
        ),
        migrations.AddConstraint(
            model_name="role",
            constraint=models.UniqueConstraint(
                fields=("display_name", "tenant"), name="unique role display name per tenant"
            ),
        ),
    ]
