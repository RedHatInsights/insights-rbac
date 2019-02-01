#
# Copyright 2019 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

"""View for group management."""
from management.group.model import Group
from management.group.serializer import GroupInputSerializer, GroupSerializer
from management.principal.model import Principal
from management.principal.serializer import PrincpalInputSerializer
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.response import Response


class GroupViewSet(mixins.CreateModelMixin,
                   mixins.DestroyModelMixin,
                   mixins.ListModelMixin,
                   mixins.RetrieveModelMixin,
                   mixins.UpdateModelMixin,
                   viewsets.GenericViewSet):
    """Group View.

    A viewset that provides default `create()`, `destroy`, `retrieve()`,
    and `list()` actions.

    """

    queryset = Group.objects.all()
    permission_classes = (AllowAny,)
    lookup_field = 'uuid'

    def get_serializer_class(self):
        """Get serializer based on route."""
        if 'principals' in self.request.path:
            return PrincpalInputSerializer
        if self.request.method == 'POST' or self.request.method == 'PUT':
            return GroupInputSerializer
        return GroupSerializer

    def create(self, request, *args, **kwargs):
        """Create a group.

        @api {post} /api/v1/groups/   Create a group
        @apiName createGroup
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Create a Group

        @apiHeader {String} token User authorization token

        @apiParam (Request Body) {String} name Group name
        @apiParamExample {json} Request Body:
            {
                "name": "GroupA"
            }

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 201 CREATED
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "GroupA",
                "principals": []
            }
        """
        return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Obtain the list of groups for the tenant.

        @api {get} /api/v1/groups/   Obtain a list of groups
        @apiName getGroups
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Obtain a list of groups

        @apiHeader {String} token User authorization token

        @apiParam (Query) {String} name Filter by group name.

        @apiSuccess {Number} count The number of groups.
        @apiSuccess {String} previous  The uri of the previous page of results.
        @apiSuccess {String} next  The uri of the next page of results.
        @apiSuccess {Object[]} data  The array of group results.

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                'count': 2,
                'next': None,
                'previous': None,
                'data': [
                                {
                                    "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                                    "name": "GroupA"
                                },
                                {
                                    "uuid": "20ecdcd0-397c-4ede-8940-f3439bf40212",
                                    "name": "GroupB"
                                }
                            ]
            }

        """
        return super().list(request=request, args=args, kwargs=kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Get a group.

        @api {get} /api/v1/groups/:uuid   Get a group
        @apiName getGroup
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Get a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier.

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccess {Array} principals Array of principals
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "GroupA",
                "principals": [
                    { "username": "jsmith" }
                ]
            }
        """
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete a group.

        @api {delete} /api/v1/groups/:uuid   Delete a group
        @apiName deleteGroup
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Delete a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} uuid Group unique identifier

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 204 NO CONTENT
        """
        return super().destroy(request=request, args=args, kwargs=kwargs)

    def update(self, request, *args, **kwargs):
        """Update a group.

        @api {post} /api/v1/groups/:uuid   Update a group
        @apiName updateGroup
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Update a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "GroupA"
            }
        """
        return super().update(request=request, args=args, kwargs=kwargs)

    def add_principals(self, group, principals):
        """Process list of principals and add them to the group."""
        for input in principals:
            username = input['username']
            try:
                principal = Principal.objects.get(username=username)
            except Principal.DoesNotExist:
                principal = Principal(username=username)
                principal.save()
            group.principals.add(principal)
        group.save()
        return group

    def remove_principals(self, group, principals):
        """Process list of principals and remove them from the group."""
        for input in principals:
            username = input['username']
            try:
                principal = Principal.objects.get(username=username)
            except Principal.DoesNotExist:
                principal = Principal(username=username)
                principal.save()
            group.principals.remove(principal)
        group.save()
        return group

    @action(detail=True, methods=['post', 'delete'])
    def principals(self, request, uuid=None):
        """Add or remove principals from a group.

        @api {post | delete} /api/v1/groups/:uuid/princpals/   Add or remove a princpal
        @apiName addOrRemovePrincipals
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Add or remove principals from a group

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Group unique identifier

        @apiParam (Request Body) {String} username Principal username
        @apiParamExample {json} Request Body:
            [
                {
                    "username": "jsmith"
                },
                {
                    "username": "ksmith"
                }
            ]

        @apiSuccess {String} uuid Group unique identifier
        @apiSuccess {String} name Group name
        @apiSuccess {Array} principals Array of principals
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "GroupA",
                "principals": [
                    { "username": "jsmith" }
                ]
            }
        """
        group = self.get_object()
        serializer = PrincpalInputSerializer(data=request.data, many=True)
        principals = None
        if serializer.is_valid():
            principals = serializer.data[:]
        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)
        if request.method == 'POST':
            group = self.add_principals(group, principals)
            output = GroupSerializer(group)
            return Response(status=status.HTTP_200_OK, data=output.data)
        else:
            self.remove_principals(group, principals)
            return Response(status=status.HTTP_204_NO_CONTENT)
