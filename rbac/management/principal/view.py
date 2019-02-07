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

"""View for principal management."""
from rest_framework import mixins, viewsets
from rest_framework.permissions import AllowAny

from .model import Principal
from .serializer import PrincpalSerializer


class PrincipalViewSet(mixins.ListModelMixin,
                       mixins.RetrieveModelMixin,
                       viewsets.GenericViewSet):
    """Principal View.

    A viewset that provides default `retrieve()`,
    and `list()` actions.

    """

    queryset = Principal.objects.all()
    serializer_class = PrincpalSerializer
    permission_classes = (AllowAny,)
    lookup_field = 'username'

    def list(self, request, *args, **kwargs):
        """Obtain the list of principals for the tenant.

        @api {get} /api/v1/principals/   Obtain a list of principals
        @apiName getPrincipals
        @apiGroup Principal
        @apiVersion 1.0.0
        @apiDescription Obtain a list of principals

        @apiHeader {String} token User authorization token

        @apiSuccess {Object} meta The metadata for pagination.
        @apiSuccess {Object} links  The object containing links of results.
        @apiSuccess {Object[]} data  The array of results.

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                'meta': {
                    'count': 2
                }
                'links': {
                    'first': /api/v1/principals/?page=1,
                    'next': None,
                    'previous': None,
                    'last': /api/v1/principals/?page=1
                },
                'data': [
                                {
                                    "username": "jsmith",
                                    "email": "jsmith@company.com"
                                },
                                {
                                    "username": "ksmith",
                                    "email": "ksmith@company.com"
                                }
                            ]
            }

        """
        return super().list(request=request, args=args, kwargs=kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Get a principal.

        @api {get} /api/v1/principal/:username   Get a principal
        @apiName getPrincipal
        @apiGroup Principal
        @apiVersion 1.0.0
        @apiDescription Get a principal

        @apiHeader {String} token User authorization token

        @apiParam (Query) {String} id Principal username.

        @apiSuccess {String} username Principal username
        @apiSuccess {String} email Pricipal email
        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                "username": "ksmith",
                "email": "ksmith@company.com"
            }
        """
        return super().retrieve(request=request, args=args, kwargs=kwargs)
