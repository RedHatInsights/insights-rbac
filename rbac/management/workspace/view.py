from rest_framework import mixins, serializers, status, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from management.workspace.serializer import WorkspaceSerializer
from rest_framework.decorators import action

from django.db.models import Q

from treebeard.exceptions import PathOverflow

from .model import Workspace
from management.permission.model import Permission
from management.role.model import Access, ResourceDefinition

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

    def _get_subtree(self, node):
        """
        """
        children = node.get_children()
        permissions = Permission.objects.filter(workspace_id=node.id)
        subtree = {
            "name": str(node.name),
            "uuid": str(node.uuid),
            "children": [self._get_subtree(child) for child in children],
            "permissions":  [permission.permission for permission in permissions]
        }
        return subtree

    def create(self, request, *args, **kwargs):
        """Create a roles.
        """
        return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Obtain the list of roles for the tenant.
        """
        response = super().list(request=request, args=args, kwargs=kwargs)

        root_nodes = Workspace.get_root_nodes()
        tree_structure = [self._get_subtree(node) for node in root_nodes]

        response.data['tree'] = tree_structure

        return response

    def retrieve(self, request, *args, **kwargs):
        """Get a role.
        """
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete a role.
        """

        return super().destroy(request=request, args=args, kwargs=kwargs)


    @action(detail=True, methods=["post"], url_path='move/(?P<target_uuid>[^/.]+)')
    def move(self, request, uuid=None, target_uuid=None):
        # Who has permission to do this ?

        # Find permission and change workspace relation
        # change workspace relation - permission could have multiple resource definitions
        # it could be operations:
        # - move: source permission has the only one resource definitions and there is no same permission
        #         in target workspace [DONE]
        # - source split and target merge[TODO]: there are multiple resource definitions of permission at source workspace and
        #                                  and same permission exists already at target workspace

        access_ids = None
        permission = None

        if 'access' in request.data and isinstance(request.data['access'], list) and len(request.data['access']) > 0:
            if 'permission' in request.data['access'][0]:
                permission_str = request.data['access'][0]['permission']

                if 'resourceDefinitions' in request.data['access'][0]:
                    resource_definitions =  request.data['access'][0]['resourceDefinitions']
                    if len(resource_definitions) > 0:
                        attribute_filter_value = resource_definitions[0]['attributeFilter']
                        if attribute_filter_value:
                            resource_definition_ids = ResourceDefinition.objects.filter(
                                attributeFilter=attribute_filter_value
                            ).values_list('access_id', flat=True)

                            if resource_definition_ids and len(resource_definition_ids) > 0:
                                access_ids = Access.objects.filter(
                                    id__in=resource_definition_ids
                                ).values_list('id', flat=True)

                source_workspace = Workspace.objects.get(uuid=uuid)

                if not access_ids:
                    permission = Permission.objects.filter(workspace=source_workspace,
                                    permission=permission_str
                                ).distinct()
                else:
                    permission = Permission.objects.filter(
                                    workspace=source_workspace,
                                    permission=permission_str,
                                    accesses__id__in=list(access_ids)
                                ).distinct()

                if permission and permission.count() > 1:
                    return Response({"error": "Multiple permissions match the query. Please refine your criteria."},
                                    status=status.HTTP_404_NOT_FOUND)

                if permission.count() == 0:
                    return Response({"error": "HTTP_404_NOT_FOUND"},
                                    status=status.HTTP_404_NOT_FOUND)

        permission = permission.first()

        if not permission:
            return Response({"error": "Permission not found in source workspace"},
                            status=status.HTTP_404_NOT_FOUND)

        if not access_ids:
            # standalone permission
            permission.change_workspace_to(target_uuid)
        else:
            # we need to split resource definitions
            permission.change_workspace_to(target_uuid)

        return Response(permission.permission, status=status.HTTP_201_CREATED)

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
