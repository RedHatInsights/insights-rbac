# Generated by Django 3.2.16 on 2023-01-27 19:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0038_auto_20220512_1800'),
    ]

    operations = [
        migrations.AlterField(
            model_name='resourcedefinition',
            name='attributeFilter',
            field=models.JSONField(default=dict),
        ),
    ]
