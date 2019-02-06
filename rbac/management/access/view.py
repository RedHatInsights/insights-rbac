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

"""View for principal access."""
from django.utils.translation import gettext as _
from management.models import Principal
from management.role.serializer import AccessSerializer
from rest_framework import serializers, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

APPLICATION_KEY = 'application'
USERNAME_KEY = 'username'


def _policies_for_groups(groups):
    """Gathers all policies for the given groups."""
    policies = []
    for group in set(groups):
        group_policies = set(group.policies.all())
        policies += group_policies
    return policies


def _roles_for_policies(policies):
    """Gathers all roles for the given policies."""
    roles = []
    for policy in set(policies):
        policy_roles = set(policy.roles.all())
        roles += policy_roles
    return roles


def _access_for_roles(roles, application):
    """Gathers all access for the given roles and application."""
    access = []
    for role in set(roles):
        role_access = set(role.access.all())
        for access_item in role_access:
            if application in access_item.permission:
                serializer = AccessSerializer(access_item)
                access.append(serializer.data)
    return access


@api_view(['GET'])
@permission_classes([AllowAny])
def access(request):
    """Obtain principal access list.

    @api {get} /api/v1/access/   Obtain principal access list
    @apiName getPrincipalAccess
    @apiGroup Access
    @apiVersion 1.0.0
    @apiDescription Obtain principal access list

    @apiHeader {String} token User authorization token

    @apiParam (Query) {String} application Application name
    @apiParam (Query) {String} username Principal username

    @apiSuccess {Array} access Array of principal access objects
    @apiSuccessExample {json} Success-Response:
        HTTP/1.1 20O OK
        {
            "access": [
                {
                    "permission": "app:*:read",
                    "resourceDefinition": [
                        {
                            "attributeFilter": {
                                "key": "app.attribute.condition",
                                "value": "value1",
                                "operation": "equal"
                            }
                        }
                    ]
                }
            ]
        }
    """
    principal = None
    required_parameters = [APPLICATION_KEY, USERNAME_KEY]
    have_parameters = all(param in request.query_params for param in required_parameters)

    if not have_parameters:
        key = 'detail'
        message = 'Query parameters [{}] are required.'.format(', '.join(required_parameters))
        raise serializers.ValidationError({key: _(message)})

    username = request.query_params.get(USERNAME_KEY)
    app = request.query_params.get(APPLICATION_KEY)

    try:
        principal = Principal.objects.get(username=username)
    except Principal.DoesNotExist:
        key = 'detail'
        message = 'No access found for principal with username {}.'.format(username)
        raise serializers.ValidationError({key: _(message)})

    groups = set(principal.group.all())
    policies = _policies_for_groups(groups)
    roles = _roles_for_policies(policies)
    access = _access_for_roles(roles, app)

    return Response({'access': access}, status=status.HTTP_200_OK)
