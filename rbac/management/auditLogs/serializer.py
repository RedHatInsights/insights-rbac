from management.models import AuditLogModel
from rest_framework import serializers 



# db_object = AuditLogModel(requester="jdoe", description="foo", resource=AuditLogModel.GROUP, action=AuditLogModel.ADD) 
# db_object.save() 


class AuditLogSerializer(serializers.ModelSerializer):

    requester = serializers.CharField(required = True, max_length = 255)
    description = serializers.CharField(required = True, max_lenth = 255)
    resource = serializers.CharField(required = True, max_length = 255)
    action  = serializers.CharField(required = True, max_length = 255)

    class Meta:
        model = AuditLogModel
        fields = ("requester", "description", "resource", "action")


