# Generated by Django 4.2.15 on 2024-08-28 10:27

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0049_remove_rolemapping_v1_role_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='BindingMapping',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('mappings', models.JSONField(default=dict)),
                ('role', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='binding_mapping', to='management.role')),
            ],
        ),
    ]
