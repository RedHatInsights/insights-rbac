
from rest_framework import serializers
from django.db import connection

from .model import Workspace


class WorkspaceChildrenSerializer(serializers.ModelSerializer):
    name = serializers.CharField(required=True, max_length=150)
    uuid = serializers.UUIDField(read_only=True)

    class Meta:
        """Metadata for the serializer."""

        model = Workspace
        fields = ("name", "uuid",)

    def create(self, validated_data):
        name = validated_data.pop("name")
        tenant = self.context["request"].tenant

        workspace = Workspace.add_root(name=name, tenant=tenant)
        return workspace

    def update(self, instance, validated_data):
        return {}

class WorkspaceSerializer(serializers.ModelSerializer):
    name = serializers.CharField(required=True, max_length=150)
    uuid = serializers.UUIDField(read_only=True)
    children = WorkspaceChildrenSerializer(read_only=True, many=True)

    class Meta:
        """Metadata for the serializer."""

        model = Workspace
        fields = ( "name", "uuid", "children")

    def create(self, validated_data):
        name = validated_data.pop("name")
        tenant = self.context["request"].tenant

        workspace =  Workspace.add_root(name=name, tenant=tenant)
        return workspace

    def update(self, instance, validated_data):

        return {}
