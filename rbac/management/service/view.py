from rest_framework import mixins, serializers, status, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from management.service.serializer import ServiceSerializer, ServiceAccessSerializer
from rest_framework.decorators import action

from django.db.models import Q

from treebeard.exceptions import PathOverflow

from .model import Service, ServiceAccess
from management.permission.model import Permission
from management.role.model import Access, ResourceDefinition
from api.models import Tenant
from datetime import datetime
from datetime import date
import uuid

class ServiceViewSet( mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,):

    permission_classes = (AllowAny,)
    queryset = Service.objects.all()
    lookup_field = "uuid"
    serializer_class = ServiceSerializer

    def create(self, request, *args, **kwargs):
        """Create a service.
        """
        return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Obtain the list of services for the tenant.
        """
        response = super().list(request=request, args=args, kwargs=kwargs)

        return response


class ServiceAccessViewSet( mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,):

    permission_classes = (AllowAny,)
    queryset = ServiceAccess.objects.all()
    lookup_field = "uuid"
    serializer_class = ServiceAccessSerializer

    def create(self, request, *args, **kwargs):
        """Create service access.
        """
        access = False
        tenant_name = request.data.pop("tenant")
        service_uuid = request.data.pop("service")
        start_date = request.data.get("start_date")
        start_date = datetime.strptime(start_date, "%Y-%m-%d").date()
        end_date = request.data.get("end_date")
        end_date = datetime.strptime(end_date, "%Y-%m-%d").date()
        service = Service.objects.filter(uuid=service_uuid).first()
        tenant = Tenant.objects.filter(tenant_name=tenant_name).first()
        # check if today falls between start date and end date
        today = date.today()
        if start_date <= today <= end_date:
            access = True
        request.data["access"] = access
        request.data["tenant"] = tenant.id
        request.data["service"] = service.id
        return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Obtain the list of services for the tenant.
        """
        query_params = request.query_params
        if query_params.get("check_access"):
            # http://127.0.0.1:9080/api/rbac/v1/service_accesses/?tenant=acct10001&service=99f88439-2e63-4090-891a-435e5d8a5568&check_access=True
            service_uuid = query_params.get("service")
            service_uuid = uuid.UUID(service_uuid)
            tenant_name = query_params.get("tenant")
            service = Service.objects.filter(uuid=service_uuid).first()
            tenant = Tenant.objects.filter(tenant_name=tenant_name).first()
            AccessObject = ServiceAccess.objects.filter(tenant_id=tenant.id, service_id=service.id).first()
            if AccessObject:
                has_access = AccessObject.access
            return Response(
                    {
                        "has_access": has_access,
                        "tenant": tenant_name,
                        "service": service_uuid,
                    }
                )
        elif query_params.get("list_services"):
            # http://127.0.0.1:9080/api/rbac/v1/service_accesses/?tenant=acct10001&list_services=True
            tenant_name = query_params.get("tenant")
            tenant = Tenant.objects.filter(tenant_name=tenant_name).first()
            AccessObjects = ServiceAccess.objects.filter(tenant_id=tenant.id, access=True)
            service_ids = [access.service_id for access in AccessObjects]
            service_uuids = []
            for serv_id in service_ids:
                Service_obj = Service.objects.filter(id=serv_id).first()
                service_uuids.append(Service_obj.uuid)
            return Response(
                    {
                        "tenant": tenant_name,
                        "services": service_uuids,
                    }
                )
        elif query_params.get("list_tenants"):
            # http://127.0.0.1:9080/api/rbac/v1/service_accesses/?service=99f88439-2e63-4090-891a-435e5d8a5568&list_tenants=True
            service_uuid = query_params.get("service")
            service_uuid = uuid.UUID(service_uuid)
            service_obj = Service.objects.filter(uuid=service_uuid).first()
            AccessObjects = ServiceAccess.objects.filter(service_id=service_obj.id, access=True)
            tenant_ids = [access.tenant_id for access in AccessObjects]
            tenant_names = []
            for ten_id in tenant_ids:
                tenant_obj = Tenant.objects.filter(id=ten_id).first()
                tenant_names.append(tenant_obj.tenant_name)
            return Response(
                    {
                        "service": service_uuid,
                        "tenants": tenant_names,
                    }
                )
        response = super().list(request=request, args=args, kwargs=kwargs)

        return response