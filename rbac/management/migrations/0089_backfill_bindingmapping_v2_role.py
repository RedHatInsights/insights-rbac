from django.db import migrations


def backfill_v2_role(apps, schema_editor):
    """Backfill v2_role FK from mappings JSON field."""
    BindingMapping = apps.get_model("management", "BindingMapping")
    RoleV2 = apps.get_model("management", "RoleV2")

    needed_uuids = set()
    for bm in BindingMapping.objects.filter(v2_role__isnull=True).iterator(chunk_size=1000):
        role_data = bm.mappings.get("role")
        if role_data and "id" in role_data:
            needed_uuids.add(str(role_data["id"]))

    v2_role_lookup = {str(r.uuid): r.pk for r in RoleV2.objects.filter(uuid__in=needed_uuids).only("id", "uuid")}

    batch = []
    updated = 0
    skipped = 0

    for bm in BindingMapping.objects.filter(v2_role__isnull=True).iterator(chunk_size=1000):
        role_data = bm.mappings.get("role")
        if not role_data or "id" not in role_data:
            skipped += 1
            continue

        v2_role_pk = v2_role_lookup.get(str(role_data["id"]))
        if v2_role_pk is None:
            skipped += 1
            continue

        bm.v2_role_id = v2_role_pk
        batch.append(bm)

        if len(batch) >= 1000:
            BindingMapping.objects.bulk_update(batch, ["v2_role_id"])
            updated += len(batch)
            batch = []

    if batch:
        BindingMapping.objects.bulk_update(batch, ["v2_role_id"])
        updated += len(batch)


class Migration(migrations.Migration):

    dependencies = [
        ("management", "0088_bindingmapping_v2_role_and_indexes"),
    ]

    operations = [
        migrations.RunPython(backfill_v2_role, migrations.RunPython.noop),
    ]
