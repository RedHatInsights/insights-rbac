"""Serializer for Services."""
from management.models import Service, ServiceAccess
from api.models import Tenant
from rest_framework import serializers

class ServiceSerializer(serializers.Serializer):
    """Serializer for the Service model."""

    name = serializers.CharField(required=True, max_length=150)

    class Meta:
        """Metadata for the serializer."""

        fields = ("name","uuid",)

    def create(self, validated_data):
        name = validated_data.pop("name")
        service = Service(name=name)
        service.save()
        return service

class ServiceAccessSerializer(serializers.ModelSerializer):
    """Serializer for the service access model."""
    start_date = serializers.DateTimeField(format="%d %b %Y")
    end_date = serializers.DateTimeField(format="%d %b %Y")
    access = serializers.BooleanField(read_only=False)

    class Meta:
        """Metadata for the serializer."""

        model = ServiceAccess
        fields = (
            "tenant",
            "start_date",
            "end_date",
            "service",
            "access",
        )

    def create(self, validated_data):
        tenant = validated_data.pop("tenant")
        service = validated_data.pop("service")
        has_access = validated_data.pop("access")
        start_date = validated_data.pop("start_date")
        end_date = validated_data.pop("end_date")
        access = ServiceAccess(start_date=start_date, end_date=end_date, service_id=service.id, tenant_id=tenant.id, access=has_access)
        access.save()
        return access
