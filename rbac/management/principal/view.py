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
        """Obtain the list of principal for the tenant.

        @api {get} /api/v1/principal/   Obtain a list of principal
        @apiName getPrincipals
        @apiGroup Principal
        @apiVersion 1.0.0
        @apiDescription Obtain a list of principal

        @apiHeader {String} token User authorization token

        @apiSuccess {Number} count The number of principal.
        @apiSuccess {String} previous  The uri of the previous page of results.
        @apiSuccess {String} next  The uri of the next page of results.
        @apiSuccess {Object[]} data  The array of pricipal results.

        @apiSuccessExample {json} Success-Response:
            HTTP/1.1 200 OK
            {
                'count': 2,
                'next': None,
                'previous': None,
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
