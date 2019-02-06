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

"""View for role management."""
from rest_framework import mixins, viewsets
from rest_framework.permissions import AllowAny

from .model import Role
from .serializer import RoleSerializer


class RoleViewSet(mixins.CreateModelMixin,
                  mixins.DestroyModelMixin,
                  mixins.ListModelMixin,
                  mixins.RetrieveModelMixin,
                  mixins.UpdateModelMixin,
                  viewsets.GenericViewSet):
    """Role View.

    A viewset that provides default `create()`, `destroy`, `retrieve()`,
    and `list()` actions.

    """

    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = (AllowAny,)
    lookup_field = 'uuid'

    def create(self, request, *args, **kwargs):
        """Create a roles.

        @api {post} /api/v1/roles/   Create a role
        @apiName createRole
        @apiGroup Role
        @apiVersion 1.0.0
        @apiDescription Create a role

        @apiHeader {String} token User authorization token

        @apiParam (Request Body) {String} name Role name
        @apiParam (Request Body) {Array} access Access definition
        @apiParamExample {json} Request Body:
            {
                "name": "RoleA",
                "access": [
                    {
                    "permission": "app:*:read",
                    "resourceDefinition": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.case",
                                "operation": "equal",
                                "value": "thevalue"
                            }
                        }
                    ]
                    }
                ]
            }

        @apiSuccess {String} uuid Role unique identifier
        @apiSuccess {String} name Role name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 201 CREATED
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "RoleA",
                "access": [
                    {
                    "permission": "app:*:read",
                    "resourceDefinition": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.case",
                                "operation": "equal",
                                "value": "thevalue"
                            }
                        }
                    ]
                    }
                ]
            }
        """
        return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Obtain the list of roles for the tenant.

        @api {get} /api/v1/roles/   Obtain a list of roles
        @apiName getRoles
        @apiGroup Role
        @apiVersion 1.0.0
        @apiDescription Obtain a list of roles

        @apiHeader {String} token User authorization token

        @apiParam (Query) {String} name Filter by role name.

        @apiSuccess {Number} count The number of roles.
        @apiSuccess {String} previous  The uri of the previous page of results.
        @apiSuccess {String} next  The uri of the next page of results.
        @apiSuccess {Object[]} data  The array of role results.

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                'meta': {
                    'count': 2
                }
                'links': {
                    'first': /api/v1/roles/?page=1,
                    'next': None,
                    'previous': None,
                    'last': /api/v1/roles/?page=1
                },
                'data': [
                            {
                                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                                "name": "RoleA"
                            },
                            {
                                "uuid": "20ecdcd0-397c-4ede-8940-f3439bf40212",
                                "name": "RoleB"
                            }
                        ]
            }

        """
        return super().list(request=request, args=args, kwargs=kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Get a role.

        @api {get} /api/v1/roles/:uuid   Get a role
        @apiName getRole
        @apiGroup Role
        @apiVersion 1.0.0
        @apiDescription Get a role

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Role unique identifier.

        @apiSuccess {String} uuid Role unique identifier
        @apiSuccess {String} name Role name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "RoleA",
                "access": [
                    {
                    "permission": "app:*:read",
                    "resourceDefinition": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.case",
                                "operation": "equal",
                                "value": "thevalue"
                            }
                        }
                    ]
                    }
                ]
            }
        """
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete a role.

        @api {delete} /api/v1/roles/:uuid   Delete a role
        @apiName deleteRole
        @apiGroup Role
        @apiVersion 1.0.0
        @apiDescription Delete a role

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} uuid Role unique identifier

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 204 NO CONTENT
        """
        return super().destroy(request=request, args=args, kwargs=kwargs)

    def update(self, request, *args, **kwargs):
        """Update a group.

        @api {post} /api/v1/roles/:uuid   Update a role
        @apiName updateRole
        @apiGroup Role
        @apiVersion 1.0.0
        @apiDescription Update a role

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Role unique identifier

        @apiParam (Request Body) {String} name Role name
        @apiParam (Request Body) {Array} access Access definition
        @apiParamExample {json} Request Body:
            {
                "name": "RoleA",
                "access": [
                    {
                    "permission": "app:*:read",
                    "resourceDefinition": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.case",
                                "operation": "equal",
                                "value": "change_value"
                            }
                        }
                    ]
                    }
                ]
            }

        @apiSuccess {String} uuid Role unique identifier
        @apiSuccess {String} name Role name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "RoleA",
                "access": [
                    {
                    "permission": "app:*:read",
                    "resourceDefinition": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.case",
                                "operation": "equal",
                                "value": "change_value"
                            }
                        }
                    ]
                    }
                ]
            }
        """
        return super().update(request=request, args=args, kwargs=kwargs)
