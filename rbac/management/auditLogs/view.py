from management.models import AuditLogModel
from management.serializers import AuditLogSerializer
from rest_framework import mixins, viewsets
from rest_framework.permissions import AllowAny



class AuditLogViewSet(mixins.ListModelMixin,
                      mixins.CreateModelMixin,
                      viewsets.GenericViewSet):
    
    queryset = AuditLogModel.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = (AllowAny,)


    def get(self, request, *args, **kwargs):
        return super().list(request=request, args=args, kwargs=kwargs)
    