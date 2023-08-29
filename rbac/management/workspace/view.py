from rest_framework import mixins, serializers, status, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from management.workspace.serializer import WorkspaceSerializer
from rest_framework.decorators import action

from treebeard.exceptions import PathOverflow

from .model import Workspace

class WorkspaceViewSet( mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,):

    permission_classes = (AllowAny,)
    queryset = Workspace.objects.all()
    lookup_field = "uuid"
    serializer_class = WorkspaceSerializer

    def create(self, request, *args, **kwargs):
        """Create a roles.
        """
        return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Obtain the list of roles for the tenant.
        """
        return super().list(request=request, args=args, kwargs=kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Get a role.
        """
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete a role.
        """

        return super().destroy(request=request, args=args, kwargs=kwargs)


    @action(detail=True, methods=["get", "post", "delete"], url_path='children')
    def children(self, request, uuid=None):
        try:
            parent_workspace = Workspace.objects.get(uuid=uuid)
        except Workspace.DoesNotExist:
            return Response({"detail": "Workspace not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            workspace_queryset = Workspace.objects.filter(name=request.data.get("name"), tenant=request.tenant)

            # Check if a workspace exists
            if workspace_queryset.exists():
                return Response({"detail": "Children workspace already exist."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                child_workspace = parent_workspace.add_child(name=request.data.get("name"), tenant=request.tenant)
                serializer = WorkspaceSerializer(child_workspace)
                return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"detail": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
