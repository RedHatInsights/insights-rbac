# Generated manually to remove some platform default roles

from django.db import migrations

def remove_unnecessary_platform_default_role(apps, schema_editor):
  role_names_to_remove = [
    'Custom Policies Access',
    'Migration Analytics Access'
  ]

  Role = apps.get_model('management', 'Role')
  Role.objects.filter(system=True, name__in=role_names_to_remove).delete()

class Migration(migrations.Migration):

    dependencies = [
        ('management', '0013_auto_20200128_2030'),
    ]

    operations = [
      migrations.RunPython(remove_unnecessary_platform_default_role),
    ]
