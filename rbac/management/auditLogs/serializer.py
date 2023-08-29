from management.models import AuditLogModel
from rest_framework import serializers 
from django.db import transaction
from api.models import User

# db_object = AuditLogModel(requester="jdoe", description="foo", resource=AuditLogModel.GROUP, action=AuditLogModel.ADD) 
# db_object.save() 


class AuditLogSerializer(serializers.ModelSerializer):

    class Meta:
        model = AuditLogModel
        fields = ["requester", "description", "resource", "action",]
    
    @transaction.atomic
    def create(self, instance, validated_data): 
        instance.requester = validated_data.get("requester")
        instance.description = validated_data.get("description")
        instance.resource = validated_data.get("resource")
        instance.action = validated_data.get("action")
        instance.save()
        return instance
    
