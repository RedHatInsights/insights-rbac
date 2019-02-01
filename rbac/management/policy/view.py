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

"""View for policy management."""
from rest_framework import mixins, viewsets
from rest_framework.permissions import AllowAny

from .model import Policy
from .serializer import PolicyInputSerializer, PolicySerializer


class PolicyViewSet(mixins.CreateModelMixin,
                    mixins.DestroyModelMixin,
                    mixins.ListModelMixin,
                    mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    viewsets.GenericViewSet):
    """Policy View.

    A viewset that provides default `create()`, `destroy`, `retrieve()`,
    and `list()` actions.

    """

    queryset = Policy.objects.all()
    permission_classes = (AllowAny,)
    lookup_field = 'uuid'

    def get_serializer_class(self):
        """Get serializer based on route."""
        if self.request.method == 'POST' or self.request.method == 'PUT':
            return PolicyInputSerializer
        return PolicySerializer

    def create(self, request, *args, **kwargs):
        """Create a policy.

        @api {post} /api/v1/policies/   Create a policy
        @apiName createPolicy
        @apiGroup Policy
        @apiVersion 1.0.0
        @apiDescription Create a policy

        @apiHeader {String} token User authorization token

        @apiParam (Request Body) {String} name Policy name
        @apiParam (Request Body) {String} group UUID of group
        @apiParam (Request Body) {Array} roles Array of role UUIDs
        @apiParamExample {json} Request Body:
            {
                "name": "PolicyA"
                "group": "57e60f90-8c0c-4bd1-87a0-2143759aae1c",
                "roles": [
                    "4df211e0-2d88-49a4-8802-728630224d15"
                ]
            }

        @apiSuccess {String} uuid Policy unique identifier
        @apiSuccess {String} name Policy name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 201 CREATED
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "PolicyA",
                "group": {
                    "name": "GroupA",
                    "uuid": "57e60f90-8c0c-4bd1-87a0-2143759aae1c"
                },
                "roles": [
                    {
                        "name": "RoleA",
                        "uuid": "4df211e0-2d88-49a4-8802-728630224d15"
                    }
                ]
            }
        """
        return super().create(request=request, args=args, kwargs=kwargs)

    def list(self, request, *args, **kwargs):
        """Obtain the list of policies for the tenant.

        @api {get} /api/v1/policies/   Obtain a list of policies
        @apiName getGroups
        @apiGroup Group
        @apiVersion 1.0.0
        @apiDescription Obtain a list of policies

        @apiHeader {String} token User authorization token

        @apiParam (Query) {String} name Filter by policy name.

        @apiSuccess {Number} count The number of policies.
        @apiSuccess {String} previous  The uri of the previous page of results.
        @apiSuccess {String} next  The uri of the next page of results.
        @apiSuccess {Object[]} data  The array of policy results.

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                'count': 2,
                'next': None,
                'previous': None,
                'data': [
                                {
                                    "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                                    "name": "PolicyA"
                                },
                                {
                                    "uuid": "20ecdcd0-397c-4ede-8940-f3439bf40212",
                                    "name": "PolicyB"
                                }
                            ]
            }

        """
        return super().list(request=request, args=args, kwargs=kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Get a policy.

        @api {get} /api/v1/policies/:uuid   Get a policy
        @apiName getPolicy
        @apiGroup Policy
        @apiVersion 1.0.0
        @apiDescription Get a policy

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Policy unique identifier.

        @apiSuccess {String} uuid Policy unique identifier
        @apiSuccess {String} name Policy name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "PolicyA",
                "group": {
                    "name": "GroupA",
                    "uuid": "57e60f90-8c0c-4bd1-87a0-2143759aae1c"
                },
                "roles": [
                    {
                        "name": "RoleA",
                        "uuid": "4df211e0-2d88-49a4-8802-728630224d15"
                    }
                ]
            }
        """
        return super().retrieve(request=request, args=args, kwargs=kwargs)

    def destroy(self, request, *args, **kwargs):
        """Delete a policy.

        @api {delete} /api/v1/policies/:uuid   Delete a policy
        @apiName deletePolicy
        @apiGroup Policy
        @apiVersion 1.0.0
        @apiDescription Delete a policy

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} uuid Policy unique identifier

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 204 NO CONTENT
        """
        return super().destroy(request=request, args=args, kwargs=kwargs)

    def update(self, request, *args, **kwargs):
        """Update a policy.

        @api {post} /api/v1/policies/:uuid   Update a policy
        @apiName updatePolicy
        @apiGroup Policy
        @apiVersion 1.0.0
        @apiDescription Update a policy

        @apiHeader {String} token User authorization token

        @apiParam (Path) {String} id Policy unique identifier

        @apiParam (Request Body) {String} name Policy name
        @apiParam (Request Body) {String} group UUID of group
        @apiParam (Request Body) {Array} roles Array of role UUIDs
        @apiParamExample {json} Request Body:
            {
                "name": "PolicyA"
                "group": "59e60f90-8c0c-4bd1-87a0-2143759aae1c",
                "roles": [
                    "4df211e0-2d88-49a4-8802-728630224d15"
                ]
            }

        @apiSuccess {String} uuid Policy unique identifier
        @apiSuccess {String} name Policy name
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "uuid": "16fd2706-8baf-433b-82eb-8c7fada847da",
                "name": "PolicyA",
                "group": {
                    "name": "GroupC",
                    "uuid": "59e60f90-8c0c-4bd1-87a0-2143759aae1c"
                },
                "roles": [
                    {
                        "name": "RoleA",
                        "uuid": "4df211e0-2d88-49a4-8802-728630224d15"
                    }
                ]
            }
        """
        return super().update(request=request, args=args, kwargs=kwargs)
