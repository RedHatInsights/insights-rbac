from management.models import AuditLogModel
from rest_framework import serializers 



# db_object = AuditLogModel(requester="jdoe", description="foo", resource=AuditLogModel.GROUP, action=AuditLogModel.ADD) 
# db_object.save() 


class AuditLogSerializer(serializers.ModelSerializer):

    RESOURCE_CHOICES = (
        ("group", AuditLogModel.GROUP),
        ("role", AuditLogModel.ROLE),
        ("user", AuditLogModel.USER),
        ("permission", AuditLogModel.PERMISSION),
    )
    ACTION_CHOICES = (
        ("delete", AuditLogModel.DELETE),
        ("add", AuditLogModel.ADD),
        ("edit", AuditLogModel.EDIT),
        ("create", AuditLogModel.CREATE),
        ("remove", AuditLogModel.REMOVE),
    )


    requester = serializers.CharField(required = True, max_length = 255)
    description = serializers.CharField(required = True, max_length = 255)
    resource = serializers.ChoiceField(choices = RESOURCE_CHOICES)
    action  = serializers.ChoiceField(choices = ACTION_CHOICES)

    class Meta:
        model = AuditLogModel
        fields = ("requester", "description", "resource", "action")


