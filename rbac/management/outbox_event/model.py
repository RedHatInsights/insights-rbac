from django.db import models
import uuid


class OutboxEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    aggregate_type = models.CharField(max_length=75)
    aggregate_id = models.CharField(max_length=50)
    payload = models.BinaryField()

    class Meta:
        managed = True  # Set to False if you don't want Django to manage the table (e.g., if it already exists).
